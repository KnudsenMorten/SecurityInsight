# Release notes for SecurityInsight

## v2.1.119

Latest 30 commits touching SOLUTIONS/SecurityInsight/ in the upstream monorepo monorepo:

- docs(SI): seed RELEASENOTES.md with curated human-friendly changelog (7caf0c6f)
- fix(SI _shared): emit 'Checking N modules...' banner so customers don't think it hung (a463dd2b)
- feat(SI): daily auto-refresh via scheduled Step 0 task (8c9a00f8)
- fix(SI _shared): suppress Ensure-SecurityInsightModules hashtable output (b6d75cea)
- refactor(SI): single-source module set -- Ensure-SecurityInsightModules (88cd89b1)
- refactor(SI): centralize module guards -- every engine uses _shared/Ensure-Module (ab435826)
- feat(SI): centralize Ensure-Module helper under SCRIPTS/_shared/ (6ccf68f9)
- feat(SI YAML): merge Custom queries into Locked (ship curated defaults) (28662620)
- fix(SI Step0 bootstrap): resolve latest tag then fetch tag-pinned raw (9810c130)
- fix(SI Step0): banner reads 'Step 0' not 'Step 1' (post-renumber leftover) (eb655c70)
- fix(SI Step0): per-file [UPDATE]/[PRESERVE] log so policy is visible (508bb2ce)
- docs(SI README): add v2.1.88..v2.1.108 highlights to changelog (f26470df)
- fix(SI Step0): use Invoke-WebRequest -OutFile in bootstrap, not irm | Out-File (160bffa1)
- docs(SI README): cleaner override pattern in real-world sample (0c394553)
- docs(SI README): add real-world RiskAnalysis .custom.ps1 sample (redacted) (d710a888)
- feat(SI mail): add $global:SMTPFrom for verified-sender From header (v2.1.108) (8e770613)
- fix(SI workbook): preselect '*' to dodge empty-list KQL parse error (v2.1.107) (b7658920)
- fix(SI Workbook): filters use "empty = no filter" semantics -- no default value needed (9e12fea6)
- docs(SI SetupConfigurator): add "Built by Morten Knudsen" branding (c0a1e0d2)
- feat(SI SetupConfigurator): copy-to-clipboard "run-command" button (855d0923)
- refactor(SI): renumber Steps -- install=Step0, Permissions=Step1, LA=Step2, OpenAI=Step3, PowerBI=Step4 (636efc49)
- fix(SI Workbook): use built-in value::all sentinel so "All" pre-selects reliably (da634d58)
- feat(SI IdentityAssets + Workbook): stamp SolutionVersion on identity rows too (39ec5e31)
- feat(SI RiskAnalysis + Workbook): version stamping end-to-end (929b6435)
- fix(SI Workbook): resource picker needs explicit ARG filter query (27c81fff)
- fix(SI Workbook): resource picker -- use Azure Resource Graph (queryType 1) (d8f2f81f)
- fix(SI Workbook): workspace picker at top + '*' sentinel for multi-select "All" (deccb5b7)
- feat(SI Workbook): ship Azure Monitor Workbook JSON + import doc (0a366e0b)
- docs(SI README): extend §1 Introduction with Outputs + Use-cases sections (2d898254)
- docs(SI Step5): Setup Configurator tab + PowerBI-Prerequisites doc + README (ed381c2f)

---

## Curated highlights

The auto-generated commit log above tells you **what** changed in code. This section tells you **why you care** — grouped by release, latest first, with the customer-visible impact of each bump.

Legend: 🆕 new feature · 🔧 fix · 📚 docs · 🧰 infrastructure · ⚠️ breaking (none so far in v2.1.x)

---

### v2.1.118 — Release notes actually show the full changelog

- 🔧 **Full commit history in every release's RELEASENOTES.md.** The publish workflow used a shallow clone, so `git log -n 30` only saw the tip commit and every release got a one-bullet changelog. `fetch-depth: 0` on the CI checkout fixes it — v2.1.118 onward show all 30 recent commits, as intended.

### v2.1.117 — "Did it hang?" banner

- 🔧 **Module check banner.** First run on a cold VM: the `Get-Module -ListAvailable` probe + PSGallery trust check + NuGet provider bootstrap can eat 10–60 seconds with zero output. Now prints `[MODULE] Checking N PowerShell module(s) -- this can take a moment on the first run (no output != hung)...` up front so customers stop hitting Ctrl-C.

### v2.1.116 — Daily auto-refresh from GitHub

- 🆕 **`Register-SecurityInsightDailyUpdate.ps1`** registers a Windows Scheduled Task that runs Step 0 nightly at 03:00 as SYSTEM. One-time admin setup per box, then every new release's Locked YAML + engine code + launcher templates + workbook JSON + Power BI templates land automatically. Your `LauncherConfig.custom.ps1` and `*_Custom.yaml` are never touched. README § 3.3.1 has the full recipe + `-Unregister` cleanup + air-gapped caveat.

### v2.1.115 — Module check no longer spams a hashtable

- 🔧 **Silent success.** `Ensure-SecurityInsightModules` was leaking its internal `Name / Value / True / True / True` result table to the console because callers didn't capture the return. Now discarded with `$null =` inside the helper itself.

### v2.1.114 — One canonical module set, auto-installed on first run

- 🆕 **`Ensure-SecurityInsightModules`** — a single function that installs + imports the full PowerShell module set any SecurityInsight engine could need:
  - `Az` (meta-module: Accounts, Resources, OperationalInsights, Monitor, …)
  - `Az.ResourceGraph` (not bundled in `Az` — required separately)
  - `Microsoft.Graph` + `Microsoft.Graph.Beta` (meta-modules)
  - `AzLogDcrIngestPS` (DCR ingest)
  - `MicrosoftGraphPS` (Graph helpers)
  - `ImportExcel` + `powershell-yaml`
- 🧰 **Clean-machine safety.** A freshly-built VM running any engine for the first time now pulls every dependency from PSGallery in one pass. No more "works on my box" surprises where one engine tripped on a module another engine had pre-installed.

### v2.1.113 — Centralized module helper

- 🧰 **Every engine dot-sources `_shared/Ensure-Module.ps1`.** Deleted 4 inline `function Ensure-Module` duplicates. One source of truth for install/import/short-circuit logic. No behavioural change yet — v2.1.114 shipped the canonical module set on top.

### v2.1.112 — Ship the full curated query catalog

- 🔧 **RiskAnalysis Locked YAML now ~838 KB, up from ~428 KB.** The merge of every Custom query into Locked had been sitting uncommitted on disk through v2.1.108→v2.1.111, so every community install kept pulling the pre-merge YAML. Ident identified by comparing File Explorer file sizes on the monorepo vs the release zip. Customers get the full Identity_*, Device_*, and Attack_* query families by default now.

### v2.1.111 — Step 0 bootstrap always fresh (CDN-proof)

- 🔧 **Tag-pinned bootstrap URL.** `raw.githubusercontent.com/.../main/...` is CDN-cached for up to 5 minutes, so fetching Step0.ps1 right after a release often returned the PREVIOUS version. Bootstrap recipe now resolves `releases/latest` via the API first, then fetches `.../<tag>/scripts/Step0...` — tag-pinned URLs are immutable and not edge-cached.

### v2.1.110 — Step 0 banner says "Step 0"

- 🔧 Stale "Step 1: Install / Update from GitHub" banner cleanup after the Step-folder renumber.

### v2.1.109 — Step 0 shows what it did

- 🧰 **Per-file visibility in Step 0.** Every file decision now prints `[UPDATE]` or `[PRESERVE]` so the refresh policy is auditable:
  ```
  [UPDATE]   data\SecurityInsight_RiskAnalysis_Queries_Locked.yaml  (locked content -- force-refreshed from release)
  [PRESERVE] data\SecurityInsight_RiskAnalysis_Queries_Custom.yaml
  [PRESERVE] launchers\SecurityInsight_RiskAnalysis\LauncherConfig.custom.ps1
  [OK]    copied: 175 files  (2 of which are *_Locked.* force-refreshed)  |  preserved: 4 customer file(s)
  ```
  README § 3.3 has the full policy table.

### v2.1.108 — `$global:SMTPFrom` for modern mail relays

- 🆕 **`$global:SMTPFrom`** separates the SMTP login username from the `From` header. Brevo, SendGrid, Postmark, and Microsoft 365 all reject mail where the `From` address isn't a verified sender — the relay login is not a valid From. Engine resolves `$SMTPFrom` → `$MailFrom` → `$SMTPUser` (legacy fallback) and throws clearly if all three are empty.
- 📚 **Setup Configurator** got a new "From address (verified sender)" field; README got a matching example.
- 🔧 **Bootstrap fix:** `Invoke-WebRequest -OutFile` replaces `irm | Out-File` which double-BOM'd the script on PS 5.1.

### v2.1.107 — Azure Workbook multi-select never parse-errors

- 🔧 **`*` always preselected on every multi-select dropdown** (SecurityDomain, SecuritySeverity, CriticalityTier, Subcategory). KQL guard is `'*' in ({Param}) or Col in ({Param})` — always parses, never produces `Col in ()` on a fresh import.

### v2.1.98 – v2.1.106 — Azure Monitor Workbook ships

- 🆕 **`TOOLS/AzureWorkbook/SecurityInsight-RiskAnalysis.workbook.json`** — drop-in template with workspace picker (Azure Resource Graph-backed), time-range, multi-select filters (SecurityDomain / SecuritySeverity / CriticalityTier / Subcategory), KPI tiles (total risk, open findings, critical findings, Δ vs previous run), trend/velocity charts, stale-findings table, identity inventory, and a "Data powered by" footer that shows which engine version wrote the rows.
- 🆕 **`$global:SendToPowerBI`** toggle on RiskAnalysis + new `Step4_Deploy-SecurityInsight-PowerBI-Dashboard.ps1` for one-time `.pbix` upload + parameter rebind + refresh via Power BI REST API.

### v2.1.88 – v2.1.97 — Data contract stabilizes

- 🆕 **Deterministic `TraceID` + `TraceName`** on every RiskAnalysis row. `TraceName = '<ConfigName>--<Severity>--<Tier>'`; `TraceID = SHA-256(TraceName).Substring(0,16)`. Group-by TraceID in KQL to track the same finding across runs. Separator bumped to `--` so severities containing a hyphen (e.g. `Critical - tier 0`) don't collide.
- 🆕 **`CollectionTime`** uniform across every row of a single run. `| where CollectionTime == toscalar(... summarize max(CollectionTime))` gives the latest slice. Ingest pipeline mirrors the identity engine: `Add-CollectionTimeToAllEntriesInArray` → `Add-ColumnDataToAllEntriesInArray` → `ValidateFix-AzLogAnalyticsTableSchemaColumnNames` → `Build-DataArrayToAlignWithSchema` → `Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output`.
- 🆕 **`SolutionVersion` column** on both `SI_RiskAnalysis_*_CL` and `SI_IdentityAssets_CL`. Read from `VERSION.txt` (walked up from `$PSScriptRoot`). Answers "did my scheduled cron box actually update?" with a one-line KQL: `... | distinct SolutionVersion`.

### v2.1.x (ongoing prior context)

See `§ 5 What's New` in the README for the full v2.1.0 → v2.1.64 feature matrix (auto-provisioned infrastructure, layered defaults, per-template mail routing, SPN permission validation, etc.).

