# Release notes for SecurityInsight

## v2.1.137

Latest 30 commits touching SOLUTIONS/SecurityInsight/ in the upstream monorepo monorepo:

- fix(SI CUSTOMDATA sample): use canonical 'dce-securityinsight' naming (was 'dce-si-identity') (4f535db4)
- docs(SI README): real-world .custom.ps1 samples for Identity + Build_Tier engines (7dabefd0)
- fix(SI Build_Tier): restore visible SECTION A header so AD tiering isn't invisible (9f3c41aa)
- refactor(SI Build_Tier): drop on-prem AD enumeration entirely (ff5a7cf7)
- fix(SI Build_Tier): drop dead 'AD_GroupMembership' key from tiering JSON (63cf116c)
- docs(SI README): RSAT AD PowerShell prerequisite for Build_Tier_Definitions_JSON_File (4809b66d)
- fix(SI Build_Tier): fail fast with RSAT install command when ActiveDirectory module is missing (6e7d1834)
- refactor(SI): delete every duplicate module-check leftover from the v2.1.113 refactor (53343c56)
- fix(SI ingest): filter DCE/DCR cache by RG as well as sub (kills 'westeurope' 404) (8d59f0a1)
- docs(SI): backfill curated RELEASENOTES for v2.1.120 -> v2.1.127 (d4b27a9c)
- docs(SI README): section 6.6 -- CriticalAssetTagging Mode/Scope workflow (124fc81e)
- docs(SI README): require admin PowerShell for Step 0 bootstrap (a92b428e)
- fix(SI _shared): default -Scope AllUsers + fail fast if non-elevated (0b263886)
- perf(SI _shared): drop all Import-Module calls -- trust PowerShell auto-load (ff869fb6)
- perf(SI _shared): skip Import-Module on meta-modules (Az, Microsoft.Graph, Microsoft.Graph.Beta) (314c8fe0)
- perf(SI _shared): fast directory-first module probe (fixes 30s stall on meta-modules) (4d3f37eb)
- fix(SI _shared): per-module '[MODULE] probing X ...' line so customers see which module is being checked (e8fbc177)
- fix(SI _shared): detect modules installed in AllUsers + default Scope=Auto (b7277b76)
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

---

## Curated highlights

The auto-generated commit log above tells you **what** changed in code. This section tells you **why you care** — grouped by release, latest first, with the customer-visible impact of each bump.

Legend: 🆕 new feature · 🔧 fix · 📚 docs · 🧰 infrastructure · ⚠️ breaking (none so far in v2.1.x)

---

### v2.1.133 — Drop stale `AD_GroupMembership` key from tiering JSON output

- 🧰 **`SecurityInsight_IdentityTiering.json` no longer carries the dead `AD_GroupMembership` key.** The consumer side in `IdentityAssetsCollectDefineTierIngestLog` was stripped earlier (see `# AD_GroupMembership JSON snapshot is no longer used.` comment on its line 1441) but the producer kept emitting it, leaving a `"AD_GroupMembership": [null]` stub in every regenerated catalog. The AI tiering prompt path that reads AD group membership (`-ADGroupMembership` param on the tiering function) is unchanged — members are still fed to the AI as classification context; we just don't persist the snapshot.

### v2.1.136 — Real-world `LauncherConfig.custom.ps1` samples for Identity + Build_Tier engines

- 📚 **Two new "Real-world LauncherConfig.custom.ps1 (redacted)" collapsible blocks in the README** under § 3.5, covering `IdentityAssetsCollectDefineTierIngestLog` and `Build_Tier_Definitions_JSON_File`. Mirrors the pattern of the existing RiskAnalysis real-world block (v2.1.119): working community-mode configs as actually deployed on a test VM, with GUIDs/secrets/keys replaced by `xxxxx` placeholders. Identity sample shows the cross-workspace Defender `IdentityInfo` pattern (ingest to one LA workspace, read `IdentityInfo` from another via `$DefenderWorkspaceResourceId`). Build_Tier sample shows the minimal shape: SPN + Azure OpenAI only, no LA / DCR / workspace plumbing.

### v2.1.135 — Restore visible `SECTION A` marker in Build_Tier output

- 🧰 **Engine log now shows `=== SECTION A: AD Built-in Groups (name-based AI tiering) ===` at the top** before Entra (SECTION B) and Azure (SECTION C) collection kicks in. The AI tiering for AD groups still happens inside the later `Invoke-AllAITiering` batch call, but the visible section header makes it clear that AD classification is part of the pipeline -- v2.1.134 removed the member-enumeration code and the associated log header together, which made it look like AD tiering had been dropped entirely. It hadn't. Output now also prints the catalog size (`$BuiltInADGroups.Count` names) and a one-liner explaining membership comes from the Exposure Graph.

### v2.1.134 — Remove on-prem AD enumeration from `Build_Tier_Definitions_JSON_File`

- 🧰 **SECTION A no longer touches the on-prem directory.** Group-membership analysis has already moved to the Exposure Graph inside `IdentityAssetsCollectDefineTierIngestLog` (see its line 1440-1441 comment: *"AD group memberships are sourced exclusively from the Exposure Graph"*), so enumerating members in this engine was dead work. Removed `Get-ADGroupMembersRecursive` + `Get-ADBuiltInGroupData` functions (~115 lines), the `$rawADMembers` pipeline, the `-ADGroupMembership` / `-RawADMembers` params, and the `TotalMembers` summary field.
- 🧰 **AI tiering still runs on the hardcoded `$BuiltInADGroups` name list** — the AI has enough signal in the Windows built-in group names (Domain Admins, Enterprise Admins, DnsAdmins, Account Operators, etc.) to classify tier without a member snapshot. `AD_BuiltInPermissionGroups_Tier0..3` JSON keys still populated; `IdentityAssetsCollect` consumer unchanged.
- 📚 **No RSAT prereq anymore.** The engine now runs cleanly on cloud-only community VMs and hybrid/on-prem VMs alike — no `ActiveDirectory` PowerShell module required. README callout rewritten from a WARNING about RSAT install to a NOTE explaining the Exposure-Graph-centric design. Previous v2.1.131 / v2.1.132 "install RSAT" guidance is now historical.

### v2.1.131 — `Build_Tier_Definitions_JSON_File` fails fast when RSAT AD is missing

- 🔧 **Clear RSAT install error instead of 30× `Get-ADGroup is not recognized` WARN spam.** SECTION A of the engine enumerates on-prem AD built-in groups via `Get-ADGroup` / `Get-ADUser` — cmdlets that ship with RSAT (a Windows OS feature, not a PSGallery module), so `Ensure-SecurityInsightModules` can't install them. Engine now detects the missing command at the top of `Get-ADBuiltInGroupData` and throws one clear error containing the **exact install command for your OS** (detected via `Win32_OperatingSystem.ProductType`): `Install-WindowsFeature RSAT-AD-PowerShell` for servers, `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` for Windows 10/11 clients. README § 3.5 callout added with the same install matrix + a note that cloud-only tenants can skip this engine and rely on the shipped `SecurityInsight_IdentityTiering.json` catalog.

### v2.1.130 — Kill every duplicate module-check across all engines

- 🧰 **One source of truth for module validation.** The v2.1.113 refactor centralised `Ensure-Module` but left behind three layers of parallel module checks that were still running on every engine invocation, emitting duplicate `[STEP] Validating Az modules` / `[STEP] Validating Microsoft Graph modules` lines and re-doing work `Ensure-SecurityInsightModules` already did at the top of the file:
  - `Test-AzModuleInstalled` / `Test-MicrosoftGraphInstalled` predicate functions in `SecurityInsight_RiskAnalysis.ps1` + all 3 CriticalAssetTagging engines (8 copies, deleted).
  - `Ensure-AzModules` function + call-site in `Step3_OnboardValidate-OpenAI` (deleted).
  - Ad-hoc `$requiredModules` + `Install-Module` loops in `Step2_LogAnalytics` and `Setup-SecurityInsight-CustomSecurityAttributes` (deleted).
- Engines now rely exclusively on the single `Ensure-SecurityInsightModules` call at the top. Only exception kept: `Step2` still does an explicit `Import-Module AzLogDcrIngestPS -Global -Force` because that module needs `-Global` for cross-dot-source function visibility (auto-load puts it in a child scope).

### v2.1.129 — DCE/DCR cache filters by resource group too (fixes "immutable Id 'westeurope'")

- 🔧 **`Ensure-SecurityInsightAzDceDcrCache` now filters by `-DceResourceGroup` and `-DcrResourceGroup` as well as `-SubscriptionId`.** On busy platform subscriptions with 70+ DCRs, same-name collisions inside a single sub (different RGs) were bypassing the v2.1.61/62 sub-filter and causing `Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output` to pick the wrong DCR. Symptom: `Log Ingestion API request failed. HTTP Status: 404 Response: "Data collection rule with immutable Id 'westeurope' not found."` — the Azure region name was being substituted where the immutable GUID belonged. Both IdentityAssetsCollect and RiskAnalysis engines updated to pass the DCE/DCR resource groups through to the filter.

### v2.1.127 — `Mode:` + `$global:Scope` documented for asset tagging

- 📚 **New README § 6.6 covers the two-stage test-before-prod tagging workflow** baked into CriticalAssetTagging: every YAML rule has a `Mode:` (Prod or Test); the launcher's `$global:Scope` is an array that picks which Mode(s) run this invocation. Use `@('TEST')` to dry-run a new rule in Custom.yaml without touching production tags, `@('PROD','TEST')` to run both together, `@('PROD')` *(default)* for scheduled runs. Includes the 5-step iteration loop + a TIP on overriding Locked rules via same-name Custom entries.

### v2.1.126 — README requires admin PowerShell for Step 0

- 📚 **IMPORTANT callout at the top of § 3.2.** Since v2.1.125 defaults to `-Scope AllUsers`, the Step 0 bootstrap must run from an elevated PowerShell session. Explains why (shared install path + visibility to SYSTEM for the scheduled task) and how to launch "Run as administrator."

### v2.1.125 — `-Scope AllUsers` default + fail-fast elevation check

- 🔧 **Default install scope flipped to `AllUsers`** across `Ensure-Module` and `Ensure-SecurityInsightModules`. Installs land in `C:\Program Files\WindowsPowerShell\Modules\` — shared across every user on the box, which means the daily scheduled task running as SYSTEM actually sees them.
- 🔧 **Fail-fast elevation check.** If a module is missing and the session isn't elevated, throw a clear actionable error upfront instead of letting Install-Module surface a cryptic NuGet / PackageManagement access-denied trace. Error text points to both options: re-launch as admin, or explicitly pass `-Scope CurrentUser` if per-user install is acceptable.

### v2.1.124 — Kill `Import-Module` entirely, trust PowerShell auto-load

- 🔧 **No more `Import-Module` in `Ensure-SecurityInsightModules`.** PowerShell auto-imports a module the first time any of its cmdlets is invoked (`Connect-AzAccount` → `Az.Accounts`, `ConvertFrom-Yaml` → `powershell-yaml`, `Export-Excel` → `ImportExcel`, etc.) — so eagerly importing the `Az` meta-module just force-loaded 70+ submodules for nothing. Combined with v2.1.122, the whole module check now finishes in well under 1 second on a warm VM, down from 2–5 minute stalls.

### v2.1.123 — Meta-modules installed, not imported (interim)

- 🔧 Split `Ensure-SecurityInsightModules` into install + import phases, with Az / Microsoft.Graph / Microsoft.Graph.Beta meta-modules skipping the import phase. Superseded by v2.1.124 which dropped the import phase entirely.

### v2.1.122 — Fast directory-first module probe

- 🔧 **Module detection no longer scans PSModulePath.** `Get-Module -ListAvailable -Name X` unhelpfully enumerates every module under every PSModulePath entry *before* filtering to `X`, so on a VM with 70+ Az.* submodules installed each probe stalled for 10–30 seconds. Helper now does a direct `Test-Path` on four well-known module roots (PS 5.1/7 × AllUsers/CurrentUser), reads the highest-version manifest directly, and falls back to the slow scan only if nothing is found at the standard locations.

### v2.1.121 — Per-module "probing X ..." progress line

- 🔧 **One DarkGray `[MODULE] probing <name> ...` line before each module check**, so when a slow probe stalls customers can see *which* module is currently being verified. Paired with the v2.1.117 "Checking N module(s)..." banner — no more guessing which module the engine is stuck on.

### v2.1.120 — Find modules installed in AllUsers, `-Scope Auto` default

- 🔧 **Directory-probe fallback for module detection.** `Get-Module -ListAvailable` can miss modules installed to AllUsers when the current PSModulePath doesn't include that scope, or when the manifest has no exported commands (true for `Az`, which is a pure meta-module). Added a Test-Path sweep of the 4 well-known module roots as a safety net.
- 🔧 **Default `-Scope` flipped from `CurrentUser` to `Auto`** (later flipped again to `AllUsers` in v2.1.125). Installs now follow the "elevated → AllUsers, non-elevated → CurrentUser" rule rather than always creating per-user copies that masked AllUsers ones.

### v2.1.119 — Curated human log seeded

- 📚 **`SOLUTIONS/SecurityInsight/RELEASENOTES.md`** committed with this curated changelog. The publish workflow already concatenates it after the auto-generated commit log, so every future release ships with both a machine log (what changed) and a human log (why you care).

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

