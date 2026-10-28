# SecurityInsight — delivered feature catalog

This is the delivered feature set of **SecurityInsight**, written in plain language for IT
admins, security teams and decision-makers. Everything listed here is built and in production
use. It is grouped by area and is safe to share publicly. (Status as of 2026-10-28, SecurityInsight 3.0.)

SecurityInsight turns your Microsoft security telemetry into a **risk-based, prioritized** view
of what to fix first. It profiles every asset (endpoint, identity, Azure resource, public IP),
tiers it by business criticality, scores every finding by consequence × probability, and ships
the result as ranked reports, Log Analytics tables, Excel + an executive email summary, and
optional dashboards — all **read-only**, with no agents and no schema changes to your tenant.

Chapter numbering matches the internal backlog, so a feature
keeps its chapter as it moves from planned → delivered.

**Editions.** Everything in this catalog except the *SecurityInsight Pro* chapter at the end is part of the free **Community** edition, licensed under the
PolyForm Shield License 1.0.0. **SecurityInsight Pro** adds cross-engine correlation (one object id
across every engine, plus asset properties), the ServiceNow CMDB connector and a vulnerability close-loop to ServiceNow or a SQL database. Pro is delivered only to
licensed customers -- see [pricing](https://invardia.com/pricing/), [buy](https://invardia.com/order/) or start a [60-day Pro trial](https://invardia.com/trial/); licensed customers get support at
[support@invardia.com](mailto:support@invardia.com) or [portal.invardia.com](https://portal.invardia.com/) › Support. Without a licence, SecurityInsight runs as the Community edition with every
feature here working normally.

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
- **One machine is one endpoint row.** ✅ 2026-10-05 — the duplicate device records Exposure Graph and
  Defender keep for the same machine are merged into one profile row, so a machine is no longer counted,
  tiered and reported twice.
- **One Azure resource is one row.** ✅ 2026-10-05 — Exposure Graph and Azure Resource Graph records of the
  same resource are correlated into one profile row.
- **The public IPs of your Azure resources are profiled too**, not only those of devices. ✅ 2026-10-05
- **Identities whose sign-in history is unavailable are profiled too.** ✅ 2026-10-05 — so a privileged
  account that never signs in is no longer left out of the identity reports (the earlier behaviour is one
  setting away).
- **A run that did not publish everything says so.** ✅ 2026-10-05 — when the upload to Log Analytics is
  incomplete, the run ends *partial* with the reason in its run-health record instead of reporting success, and
  Risk Analysis built on it is partial too, so a finding missing from it reads as unknown, never as fixed.

- **A device name is a real name, never a raw machine id.** ✅ 2026-10-01 -- When Defender knows no host name for a device, SecurityInsight leaves its display name empty instead of filling it with the raw machine id, so a workbook never shows an identifier that reads like a hostname.
- **Disabled accounts are profiled too.** ✅ 2026-10-27 -- Disabled users, guests and disabled service principals are part of the identity profile, so an account that is switched off but still holds rights shows up in the findings instead of being left out.

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
- **Optional asset write-back to CMDB (SecurityInsight Pro).** The ServiceNow connector can push asset
  mapping back to the CMDB when you want it (opt-in).
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
- A pre-built **Azure Monitor Workbook** for visual exploration -- the Community edition's dashboard. SecurityInsight Pro has its own web app.
- **Run-health alerting.** A simple KQL alert fires when a run starts but never finishes.

- **Your Risk Analysis data reaches Log Analytics complete.** ✅ 2026-08-08 — every column produced by
  a report is included in the ingest schema, so nothing is dropped between the report and the table.
- **Detailed results land in the Detailed table.** ✅ 2026-08-07 — Detailed and Summary runs are routed
  to their own destinations rather than sharing one.
- **A finished run can no longer be lost at the final write.** ✅ 2026-08-18 — a column-naming clash
  between two reports used to discard a completed run's entire output at the last step. The workbook
  is now written regardless, and the accompanying `.json` and Log Analytics data are unaffected.

- **Every value reaches Log Analytics, decimals included.** ✅ 2026-09-29 -- Log Analytics silently drops a value whose type does not match its column. SecurityInsight reads each table's column types before it uploads and converts every value to them; a decimal CVSS score in a whole-number column is also kept exactly in a companion column, and a value that still cannot land is reported.
- **Mail from a shared mailbox that can send from nowhere else.** ✅ 2026-10-07 -- You choose how SecurityInsight sends every mail: a Microsoft 365 shared mailbox (recommended), your own SMTP relay, or no mail. With the shared mailbox, the setup script creates the mailbox and limits SecurityInsight to sending from that one mailbox, and SecurityInsight checks that limit before it sends.
- **Copying report rows to Log Analytics is your choice, and off by default.** ✅ 2026-10-28 -- The Pro web app, the vulnerability connectors and the trends read the Risk Analysis results from the SecurityInsight database. Copying the report rows and the findings per asset into Log Analytics is an optional output you switch on in Settings; an update switches the copy off on an install that never chose it, so no data is written twice.

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
- **The CVE reports see every vulnerability Defender lists.** ✅ 2026-09-28 — vulnerabilities are read from
  Defender Vulnerability Management directly, not only from the Exposure Graph, which carried about two in
  three of them.
- **Summary reports keep every asset when a report is split.** ✅ 2026-09-29 — a large Summary report divided
  into parts used to keep the assets of one part only; the devices with the most CVEs could be missing from it.
- **Defender for Cloud recommendations in their own reports.** ✅ 2026-10-01 — the azure engine collects
  Defender for Cloud recommendations and their CVEs, including those the Exposure Graph does not carry, and two
  reports rank them. A recommendation on a virtual machine is listed once, under the machine, and scored by what
  the machine is (a domain controller is Tier 0 even without a tag); a subscription-wide recommendation names the
  subscription, not its raw id (✅ 2026-10-02).
- **The AI executive summary can no longer cost you a run or reorder your Top 50.** ✅ 2026-09-29 — a timeout of
  the AI service no longer ends a Risk Analysis run whose data is already published, and scores reach the AI as
  plain numbers on every regional format, so it never re-ranks the Top-50 assets.
- **The weight columns are filled on every Detailed report.** ✅ 2026-09-29
- **You choose whether the Summary and Detailed reports show the same figures.** ✅ 2026-09-07 — the
  two reports count different things and always will: Summary counts distinct **assets**, Detailed
  counts individual **asset findings**, so the same estate produces different totals in each. Both
  mails now say so in a line under the Risk Score, instead of leaving the reader to wonder. Where
  management receives **both** reports you can have them show one agreed set of figures; where
  management receives **one**, each report shows its own. Which report's figures the other adopts is
  your choice too, and it no longer depends on which run happened to finish first — so the numbers an
  executive sees stay stable from day to day instead of changing with the schedule.

- **A finding's asset id is always an asset.** ✅ 2026-10-01 -- When a finding cannot be matched to an asset, its asset id stays empty instead of carrying the recommendation's own id, so a ticketing system or CMDB never keys a record on a recommendation.
- **Report rows are never stored half empty.** ✅ 2026-10-05 -- If a Risk Analysis run would publish rows whose key columns are empty, SecurityInsight stops the post and marks the run as failed instead of storing rows you cannot report on. Each run posts through the data collection rule it is configured for and checks that the rule covers every column first.
- **Defender for Cloud fix text reads as plain text.** ✅ 2026-10-27 -- The remediation steps of a Defender for Cloud recommendation arrive in reports, Excel and mail as readable text: links keep their address, list items become lines, and no HTML tag is left.
- **Public-IP reports run on your real scan data.** ✅ 2026-10-27 -- The public-IP reports read the current public-IP profile columns, so a run with scan data completes with every row it expects instead of failing with a query error.
- **Azure recommendation reports are complete whether Defender for Cloud runs or not.** ✅ 2026-10-27 -- A recommendation is moved to the Defender for Cloud report only when that report runs, and every run checks that each expected row was retrieved and stored.
- **The mail subject names your tenant.** ✅ 2026-10-27 -- A Risk Analysis mail shows your tenant's primary domain next to its id in the subject and the header, on every kind of install.
- **Every finding carries its fix.** ✅ 2026-10-27 -- Each finding says how to fix it; a vulnerability also names the affected software and the recommended security update, in the reports, the web app and the exports.
- **Mails that read well on a phone.** ✅ 2026-10-27 -- Every SecurityInsight mail opens with a short summary, then one line per fact with the topic in bold and space between the parts -- no tables.

## 8. Severity, criticality & the tier model

- **A clear Tier 0–3 model.** Every asset lands in a tier with a documented meaning (Tier 0 =
  highest-impact / crown-jewel, down to Tier 3 = low impact), driving the probability side of the
  Risk Score and the scope of each report.
- **Traceable verdicts.** Tier decisions are fully introspectable — you can see which signals and
  top matches drove an asset's tier, so the "why" behind every classification is auditable.
- **Compliance-aligned.** The asset inventory + risk-classification model supports NIS2, DORA,
  ISO 27001 and GDPR Art. 32 evidence needs.

- **Every finding carries its asset's tier.** ✅ 2026-09-28 -- However a report links a finding to its asset (by id, name, resource path or device name), the tier, CMDB values and exclusion tags come along, so a recommendation on a Tier 0 resource is scored as Tier 0, not as the lowest tier.
- **Azure recommendations on virtual machines and subscriptions get a tier too.** ✅ 2026-10-01 -- A virtual machine that the Exposure Graph names by its full host name is matched to its Azure profile by short name, and a subscription-level recommendation takes the tier of the subscription's most critical resource, so these findings are scored by what they affect.
- **No unclassified assets.** ✅ 2026-10-27 -- Every asset gets a tier. An asset that no rule decides gets the default tier from a rule you can see and change, so nothing appears as "Unclassified".

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
- **An upgrade from 2.2 that arrives unprepared keeps working.** ✅ 2026-10-05 — a 2.2 install that receives 3.0
  without anyone reading the upgrade notes runs every engine with its unchanged scheduled tasks and configuration;
  the first run explains once what changed (the upgrade itself, a retired Power BI setting, a configured dry run
  that is now ignored, the status reports and how to turn them off). Your 2.2 data stays queryable next to the new
  rows.

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
- **No PowerShell modules.** ✅ 2026-10-05 — every engine calls Azure, Microsoft Graph and Defender over REST and
  sends its data through the Log Ingestion API itself, on Windows PowerShell 5.1 and PowerShell 7 alike. Nothing is
  installed from the PowerShell Gallery, and nothing breaks when a module elsewhere on the machine changes.
- **Run-health records are saved on every run.** ✅ 2026-10-02 — each engine writes its start and end record, so a
  failed or silent run is visible.
- **Each upload goes through the endpoint its rule is bound to**, also in a tenant with several data collection
  endpoints of the same name. ✅ 2026-10-01
- **Asset tagging has a Community launcher**, with a dry run that only reports the tags it would change. ✅ 2026-10-01

- **A container install applies every update itself.** ✅ 2026-09-30 -- When a new release reaches an install that runs in containers, SecurityInsight builds the new engine image in your own registry, moves every engine job to it and checks each one; if anything fails, every job goes back to its previous image.
- **Public-IP scanning works in containers too.** ✅ 2026-10-02 -- A container install receives its Shodan key as a Key Vault reference, so the public-IP engine fills its open-port and vulnerability fields instead of publishing them empty, and says so in one line when no key is set.
- **Container logs land in your own workspace.** ✅ 2026-10-03 -- When SecurityInsight sets up its container environment, it sends every job's console and system logs to the Log Analytics workspace you chose. You find them next to your other SecurityInsight data, and no extra workspace appears in your subscription.
- **The database is only ever extended by an update.** ✅ 2026-10-26 -- Before an update changes the SecurityInsight database, it checks every script; a statement that would drop or rewrite data is refused, also when it spans several lines or hides behind a comment.
- **One daily pipeline: Collect, Correlate, Deliver.** ✅ 2026-10-27 -- Every night one pipeline runs the three stages at the time you choose. Each step starts as soon as the steps it needs have finished, and you can run a single stage or step on its own.
- **The updater runs on its own schedule.** ✅ 2026-10-27 -- Updates are never a step of the pipeline, so an update never waits for the night's run and never holds it up.
- **Risk Analysis mail works in containers.** ✅ 2026-10-27 -- The mail password reaches the container jobs as a Key Vault reference, so a container install runs Risk Analysis and mails its result.
- **Every job gets the size it needs.** ✅ 2026-10-28 -- Each update checks the CPU and memory of every job and raises one that is too small for your tenant, never below 2 CPU and 4 GiB. A size you set yourself is kept.

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
  as Windows runs instead of falling back to a narrow default. It also uses **about five times less memory** than the old export (1.9 GB where the old needed 10 GB at the same size), so the faster path is also the one less likely to exhaust a collection host.
- **The asset build does only what changed.** ✅ 2026-10-28 -- The daily build of your assets works only on what changed since the last build, and a weekly full build checks the rest. Two builds never run at the same time: a second one waits for the first and then builds what is left.
- **Risk Analysis Detailed scales out.** ✅ 2026-10-27 -- The Detailed reports are shared over several worker jobs that run side by side, so a large estate is not processed one report after the other.
- **The data sync writes only what changed.** ✅ 2026-10-27 -- The findings per asset are replaced row by row only where they changed, and collections about to be removed are not prepared first. On a live install with a small database this more than halved the data sync, from 99.6 to 46 minutes.

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

- **Mail keeps working when your mailbox address changes.** ✅ 2026-10-07 -- When you change the primary address of the shared mailbox SecurityInsight sends from, for example to your own domain, the mail setup points the sending permission at that address. SecurityInsight keeps sending and stays limited to that one mailbox.
- **Patching after a run is not counted as a data problem.** ✅ 2026-10-18 -- When SecurityInsight checks its stored results against your live sources, a vulnerability you fixed after the collection is counted and shown as drift, not as a missing finding. Your install stays healthy while you patch, and a finding that existed at collection time but is missing still raises a warning.

## 14. Documentation

- **A clear documentation set.** A single design document describes how the system works and this
  catalog describes what it does for you — plus a detailed README front door, curated release notes,
  and video walkthroughs.

## SecurityInsight Pro

These run only with a Pro licence ([invardia.com/pricing](https://invardia.com/pricing/)); the Community edition runs without them.

- **Two editions from one code base.** ✅ 2026-09-29 — without a licence, a Pro component says so in one line and
  publishes nothing, and everything in the Community edition runs as before.
- **The licence installs, verifies and renews itself.** ✅ 2026-10-04 — a Pro install verifies its licence for its
  own tenant, and asks Invardia for a new one when it has none or it is about to end.
- **One machine is one asset across every source.** ✅ 2026-10-02 — an Azure virtual machine and its Defender device
  are correlated into one asset, so the reports show it once, with one tier.
- **Thousands of vulnerabilities to ServiceNow in minutes.** ✅ 2026-10-02 — the ServiceNow vulnerability hand-off
  sends records in batches: 12,271 real findings in under three minutes, with both sides agreeing afterwards.
- **Every engine runs in containers on a managed identity**, with AI classification through a Key Vault
  reference. ✅ 2026-10-02
- **Sample data for your ServiceNow team.** ✅ 2026-10-06 (built, not yet live) — a ServiceNow or SQL connector's page
  shows example rows on fictional demo data for everything SecurityInsight hands to ServiceNow (configuration items,
  tags, relations, proposed CIs, vulnerable items, batches), every column explained with the ServiceNow field it maps to,
  the cases to test with the result to expect, and an approval checklist; the test pack downloads as a zip (a CSV per
  object as the JDBC data source reads it, the Import Set request bodies, the how-to), and an Admin can preview the first
  rows of the install's own hand-off. The samples are generated from the shipped definitions, so they always match.
- **Template updates install themselves -- nothing to import.** ✅ 2026-10-27 — fixes to
  SecurityInsight's own reports and rules arrive with each update and are always installed; your own changes to tier
  rules, the risk index, the service model and asset tagging are never changed by an update, and Template conformance
  shows where SecurityInsight's default changed under one of them (compare, keep yours or take ours); reports and rules for
  new Microsoft data, such as a new attack-path type, arrive between updates as Microsoft content packs and are
  installed automatically -- or held for you with "Hold Microsoft content" -- and roll back with one click.
- **Undo a change, back up your configuration and restore just what you need.** ✅ 2026-10-06 (built, not yet live) —
  every change to your configuration (settings, departments and their people, access, exemptions, your template
  changes, connectors, the CMDB service model, the pipeline, reports and saved views) is recorded record by record with
  who made it, who approved it and what it was before. You can undo a commit (your own as an Admin, any as a
  SuperAdmin) -- it becomes pending changes you review and commit like any other, so an undo can be undone too. Your
  configuration is backed up every day (kept 90 days by default; pin a backup to keep it longer; a day without changes
  costs no extra copy), and "Back up now" takes one before a big change. To restore, pick a backup, see exactly what
  differs from today -- record by record, value by value -- and tick only what you want back. Backups can be downloaded
  as a signed file and imported in another environment. Secrets, the audit trail and run logs are never in a backup.
- **Release a safety check, narrowly.** ✅ 2026-10-09 — a held set of closes or a held
  collection is released by a SuperAdmin, with a reason, for the next run or a few hours at most, and only for exactly
  what was held: if it changes, it needs a new release. The Guards page shows every safety check, whether it is holding
  something right now, and -- for the ones that can never be released -- why. Optionally a second SuperAdmin must
  approve releases and restores.
- **Every safety check has its own switch.** ✅ 2026-10-06 (built, not yet live) — Settings > Guards (safety checks):
  each of the 35 safety checks can be turned off, or only its mail, and the limits that have a number can be tuned; one
  master switch turns them all off, with a plain warning of what that means. Everything is on by default. A check that
  is off says so once in its job's log and lets the step go on. The vulnerability close limit now counts the share of
  the open records only (a patch round that closes hundreds out of thousands goes through); a held collection that a
  newer complete one replaced is no longer held; rows of one broken run are reported once, not on every data sync; and
  new report columns Azure has not started storing yet no longer make a Risk Analysis run partial.
- **Send an earlier collection again, or undo a connector's last run.** ✅ 2026-10-06 (built, not yet live) — after an
  outage or a mistake, send one of the last days' collections into a vulnerability connector again (it runs through the
  connector's normal checks), or put back what the SQL vulnerability connector's last run changed. Where a connector
  cannot be undone (ServiceNow, REST), the page says so plainly.
- **Every property of an asset, from every source, on its page -- when you want it.** ✅ 2026-10-27 — choose the level under Settings > Asset properties: *security* keeps what SecurityInsight needs for risk and
  nothing more; *full* also keeps every property Entra, Intune, Defender, Azure, Exposure Graph and the
  VM extensions report, for a few days. The asset page then shows them per source, searchable by property, with lists
  kept as lists (a VM's disks and network cards as a small table, not numbered fields). No database change is needed
  when a source adds a new field.
- **Every security recommendation is a vulnerability.** ✅ 2026-10-06 (built, not yet live) — the vulnerability
  connectors carry every finding SecurityInsight reports on an asset, not only CVEs: Defender for Cloud
  recommendations, Defender security configurations, identity findings, attack paths and exposures, each with its type
  and name, opened, closed and reopened exactly like a CVE under the same safety checks. A vulnerable item and its
  configuration item carry the same key, so ServiceNow links each finding to its CI, and the Import Set push sends the
  same columns as the SQL views, with one date format.
- **Assets that are gone are retired -- after a grace period you choose per kind.** ✅ 2026-10-27 — an asset SecurityInsight no longer sees is listed under Assets & services > CMDB > Not seen anymore with its
  open findings, and retired once it has been gone longer than the grace period of its kind (client PCs, servers,
  service principals, users, Azure VMs, other Azure resources; 30 days by default, so a laptop off during a long
  holiday is not retired). An Admin can retire one early. Its findings close as "asset retired", never as fixed, and
  everything comes back if the asset does. ServiceNow gets the state on the CI row; SecurityInsight never retires or
  deletes anything in ServiceNow.
- **Full asset metadata from the same single read, with its history.** ✅ 2026-10-06 (built, not yet live) — with
  *full* on, SecurityInsight still reads each source only once: the same read that builds the security profile keeps
  every property, so nothing is collected twice and the security profile is exactly the same as at the *security*
  level. The asset page shows, per source, every snapshot kept (for the days you set) with what changed between them --
  properties added, removed or changed, and for lists the items added and removed. The separate asset-properties job is
  no longer needed; an installation that still has it keeps working (it ends at once and says so).
- **The wall board is the home page, and it opens with the risk score.** ✅ 2026-10-06 (built, not yet live) — after
  signing in, everyone who may see the wall board lands on it, and Home (first in the menu, with a home icon) and the
  logo take you back. It opens with the risk score management reads: the score and its rating in large type, one plain
  sentence ("Moderate — 22 critical and 244 high findings need attention"), the rating scale as a coloured band with a
  marker at the score, and the findings per domain (Endpoint, Identity, Azure, Public IP) by Critical, High, Medium and
  Low with a Total row -- the same figures as the Risk Analysis page and the mail. Below it, the headline numbers and the
  top Tier-0 assets as before. It keeps refreshing itself; "Full screen" shows it without the menu for a wall screen,
  and the kiosk account always sees it that way. Score left and table right on a wide screen, stacked on a phone; light
  and dark; numbers in your own number format. A person of a department still starts on their departments.
- **Every tier says who set it, and why.** ✅ 2026-10-27 -- Every asset on the tier board shows whether its tier came from a rule, your own tag or the default, and the asset page explains the tier in one sentence with every claim behind it.
- **Services ranked by weighted risk.** ✅ 2026-10-27 -- Assets & services shows each business service from your CMDB with its weighted risk, assets, findings by severity and tier, and its riskiest asset, ordered by service criticality and then risk -- or the other way round.
- **An audit trail that cannot be changed.** ✅ 2026-10-27 -- Every action in SecurityInsight is recorded with who, when, why, and the value before and after. A change a job applies on your behalf names the person who asked for it. The database itself refuses any edit or removal of the trail.
- **Your assets in a SQL CMDB table.** ✅ 2026-10-27 -- Every night the SQL CMDB connector writes every asset SecurityInsight knows into a table in your Pro database, with its history: created, changed, not seen and retired.
- **A safety check that trips sends a mail and tells support.** ✅ 2026-10-22 -- When a safety check holds or warns, the people you named get a mail with what happened, why and what to do, and Invardia support receives the same event.
- **The Risk Analysis executive view in the web app.** ✅ 2026-10-27 -- Overview shows the executive view of every run exactly as the mail shows it. In Pro, each report shows its own figures by default.
- **Updates for your update ring arrive by themselves.** ✅ 2026-10-27 -- Every day, on its own schedule, a Pro install asks Invardia for the release meant for its update ring and installs it; the licence is requested and renewed the same way. Both are on by default and can be switched off.
- **Trends count each asset once.** ✅ 2026-10-27 -- The asset counts in Changes & trends are counted per day across every split you choose, so an asset with findings in several groups is never counted twice.
- **A daily reminder of what waits for you.** ✅ 2026-10-12 -- While Get Started has a required step open or a decision waits for a SuperAdmin, one mail a day lists each open item with a link to it. It stops by itself when nothing waits.
- **What changed on an asset, over time.** ✅ 2026-10-27 -- Every asset keeps its history: owner, services, exposure, software, relations and findings, each change with before, now, source and time.
- **The database fits your tenant.** ✅ 2026-10-28 -- The Pro database is never on the Basic tier: it is created on a Standard size for your tenant with its full 250 GB of storage, and every update raises an existing database that was left smaller.
- **The web app is sized to what it uses.** ✅ 2026-10-28 -- The web app runs on 2 CPU and 4 GiB, and you can lower the Pro database size yourself. A size you set is kept by every update.
- **Invardia support keeps its database access.** ✅ 2026-10-28 -- The Invardia Support app keeps its access to your SecurityInsight database after the install and through every update, so support can help you without a new grant.
- **One incomplete report never holds the rest.** ✅ 2026-10-26 -- When one Risk Analysis report could not be completed, every other report of the run is loaded and shown, the incomplete one is named in the mail, and its last good result is kept.
- **A data health check at the end of every run.** ✅ 2026-10-27 -- Every pipeline run ends with a check of your stored results against the live sources, and the result is sent to Invardia support every day. An install that lacks the step gets it with its next update.
- **Weekly context discovery for Risk Analysis.** ✅ 2026-10-25 -- Once a week SecurityInsight reads the current columns of its sources and proposes the context fields worth mapping into the reports.
- **Support sees a run while it goes on.** ✅ 2026-10-28 -- Every half hour a Pro install tells Invardia support which step is running, when the run is expected to end, how each job did, how its sources and its database are doing and when the last mail went out -- also in the middle of a long run.

---

*Items still in progress or planned are tracked internally in the backlog. Only delivered, in-use
capabilities appear in this catalog.*

- **A fixed vulnerability is closed in your SQL database.** ✅ 2026-10-02 -- SecurityInsight keeps a vulnerability list in step with its findings: a new finding opens, a patched one closes as remediated only when the run that shows it was complete, and an asset that is missing or retired is held open or closed with its real reason.
- **The header shows how your install is updated from day one.** ✅ 2026-10-05 -- SecurityInsight records which update group your install belongs to when it is installed, so the web app header shows it from the first day instead of "not recorded" until the first update. You can also set it on the Settings page.

