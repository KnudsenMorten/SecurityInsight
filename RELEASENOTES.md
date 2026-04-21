# Release notes for SecurityInsight

## v2.1.150

Latest 30 commits touching SOLUTIONS/SecurityInsight/ in the upstream monorepo monorepo:

- fix(SI _lib Initialize-LauncherConfig): capture Layer 0 pre-existing globals + widen variable coverage (ca4aeca2)
- docs(SI CUSTOMDATA sample): complete Layer 3 template with auth / OpenAI / SMTP sections (48b129eb)
- refactor(SI Initialize-LauncherConfig): reorder layers by scope (tenant -> solution -> engine) (0c93e085)
- fix(SI LAUNCHERS): drop -RequireCustom on all community-vm templates (41e5f772)
- fix(SI Initialize-LauncherConfig): Layer 1 (LauncherConfig.defaults.ps1) is now optional (3ff3203f)
- refactor(SI LAUNCHERS): unify all 44 launcher templates on Initialize-LauncherConfig (27ac39c5)
- feat(SI CriticalAssetTagging): merge Locked+Custom by '<stem>--SI' key instead of full AssetTagName (be8136e0)
- feat(SI Initialize-LauncherConfig): per-run DATA/LOGS/config-*.log snapshot with layer provenance + secret redaction + 7-day prune (072c0340)
- feat(SI RiskAnalysis): append '--SI' source tag to every TraceName (9193d4d9)
- docs(SI README): byte-for-byte resync of sections 4.3 / 4.4 / 4.5 from c:\tmp\README.md (2cfa587a)
- docs(SI RELEASENOTES): split MEM26 resync entry to v2.1.140 (v2.1.139 already used) (804836ed)
- docs(SI README): resync sections 4.1-4.5 to verbatim text from MEM26 PDF (134fb73c)
- docs(SI README): Power BI 'Beta' + fill §5 What's-New gap from v2.1.113..v2.1.129 (544af373)
- refactor(SI LAUNCHERS): silence Test-LauncherModule success line -- engine owns the 'module present' log (84e8a20d)
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

---

## Curated highlights

The auto-generated commit log above tells you **what** changed in code. This section tells you **why you care** — grouped by release, latest first, with the customer-visible impact of each bump.

Legend: 🆕 new feature · 🔧 fix · 📚 docs · 🧰 infrastructure · ⚠️ breaking (none so far in v2.1.x)

---

### v2.1.133 — Drop stale `AD_GroupMembership` key from tiering JSON output

- 🧰 **`SecurityInsight_IdentityTiering.json` no longer carries the dead `AD_GroupMembership` key.** The consumer side in `IdentityAssetsCollectDefineTierIngestLog` was stripped earlier (see `# AD_GroupMembership JSON snapshot is no longer used.` comment on its line 1441) but the producer kept emitting it, leaving a `"AD_GroupMembership": [null]` stub in every regenerated catalog. The AI tiering prompt path that reads AD group membership (`-ADGroupMembership` param on the tiering function) is unchanged — members are still fed to the AI as classification context; we just don't persist the snapshot.

### v2.1.150 — Config snapshot captures `Layer 0 — pre-existing` + widens variable coverage

- 🧰 **`config-*.log` now answers "where is `$global:Foo` actually set?" even when the answer is "before the launcher ever ran".** A new `Layer 0 — pre-existing (session / profile / prior run)` bucket captures every relevant global that was already in the PS session when Initialize-LauncherConfig started — leaks from `$PROFILE`, a prior launcher invocation in the same session, `launcher.override.ps1`, or a parent script that set values before dot-sourcing the launcher. Previous versions only recorded what each layer changed, so pre-existing state was silently missing.
- 🧰 **Variable coverage widened from name-pattern allowlist to a built-in denylist.** Every user-defined `$global:*` (except `$Host`, `$PSCulture`, preference variables, etc.) is now captured. The old allowlist missed anything the author didn't think to add — typical case: customer's custom variable names.
- 🧰 Layer trail now opens with `Layer 0 - pre-existing   loaded   N globals inherited from session` (or `empty` / `(none)` on a clean session), making it obvious at a glance whether inherited state contributed to the effective config.

### v2.1.149 — `SecurityInsight.custom.sample.ps1` rewritten as a complete Layer 3 template

- 📚 **Solution-wide sample now shows the "auth once, inherited by every engine" pattern.** Sections added: SPN (4 methods: plaintext/cert/Key Vault/Managed Identity), Azure OpenAI, SMTP (with verified-sender note), DCR ingestion targets, cross-workspace Defender reads, subscription exclude patterns, Custom Security Attributes, AF-mode mail routing. Everything commented out with `xxxxx` placeholders so copy → edit → uncomment is a clean first-run workflow.
- 📚 **Layer precedence diagram at the top** matches v2.1.148's actual load order (tenant → solution → engine, closer wins). Previous diagram had stale pre-v2.1.148 numbering. Explicit note on community (Layer 1 platform-defaults absent) vs internal (Layer 1 populated by AF bootstrap).
- 🧰 **Recommended pattern for community VMs**: drop SPN + OpenAI + SMTP here (once), every engine's `LauncherConfig.custom.ps1` can stay empty or only carry engine-specific deltas (mail recipients, ReportTemplate override, etc.).

### v2.1.148 — Reorder config layers by scope: tenant → solution → engine, closer wins

- 🧰 **Layer precedence reordered to a strict scope hierarchy.** "Start from top, then closer wins" — broadest tenant baseline loads first, closest per-engine customer override loads last and wins. Within each scope, ours loads before customer's.

  | New # | Layer | File | Scope |
  |---|---|---|---|
  | **1** | platform-defaults | `SOLUTIONS/PlatformConfiguration/CUSTOMDATA/platform-defaults.ps1` | **Tenant** (internal mode only) |
  | **2** | shared-defaults | `LAUNCHERS/_lib/SecurityInsight.shared-defaults.ps1` | Solution (ours) |
  | **3** | SecurityInsight.custom | `SOLUTIONS/SecurityInsight/CUSTOMDATA/SecurityInsight.custom.ps1` | Solution (customer) |
  | **4** | LauncherConfig.defaults | `LAUNCHERS/<engine>/LauncherConfig.defaults.ps1` | Engine (ours) |
  | **5** | LauncherConfig.custom | `LAUNCHERS/<engine>/LauncherConfig.custom.ps1` | **Engine (customer, closest — wins)** |

- 📚 **Layer labels renumbered in `[STEP] Layer N/5: ...` output + the `config-*.log` snapshot's provenance section.** Previous numbering (Layer 0-4) had shared-defaults first — conceptually broken because `platform-defaults` is a tenant-wide layer that's broader than solution-wide. The new ordering makes the scope progression linear.
- 🔧 Load-order change is the important bit — labels are just navigation. Before: shared-defaults loaded before platform-defaults, so an internal customer's tenant variables could be silently overridden by our solution-wide defaults. After: platform baseline wins over nothing, each narrower scope overrides everything broader.

### v2.1.147 — `LauncherConfig.custom.ps1` now truly optional (drop `-RequireCustom` on community-vm)

- 🔧 **Community-vm launchers no longer pass `-RequireCustom`.** Before: the launcher threw "Per-engine customer config not found" when `LauncherConfig.custom.ps1` was absent. After: `Initialize-LauncherConfig` simply logs `[INFO] absent (...) -- skipping` and continues. If required globals (`$SpnTenantId`, SPN credentials, etc.) aren't set by any of the 5 layers, the engine itself throws downstream with a clearer error about which variable is missing.
- 🧰 **Simpler mental model** — every layer (0–4) is now consistent: present → load, absent → skip with an info line. No special-cased "hard-required" layer. Bonus: the backtick-continuation bug in 6 templates that shipped with v2.1.145 goes away because there's no longer a trailing `-RequireCustom` line to continue to.

### v2.1.146 — Layer 1 (`LauncherConfig.defaults.ps1`) now optional

- 🔧 **Initialize-LauncherConfig no longer throws when Layer 1 is absent.** The 6 engines migrated to the unified flow in v2.1.145 (CAT family, Setup-CSA, Step2/3) never shipped a per-engine `LauncherConfig.defaults.ps1` because Layer 0 shared-defaults + customer overrides already covered everything. Loader now logs `[INFO] absent ... skipping (engine has no shipped baseline; Layer 0 + customer overrides are sufficient)` and continues. Only reasonable requirement left: Layer 0 shared-defaults OR Layer 4 per-engine custom must exist, otherwise there's nothing to run.

### v2.1.145 — Every launcher flavour now uses the unified `Initialize-LauncherConfig` flow

- 🧰 **All 44 launcher templates now use the same layered-config loader** regardless of community vs internal, vm vs azure. 24 templates were still on the older direct-dot-source pattern (or missing a config-load step entirely) — migrated in this release.
  - **Consistency win #1: `.custom.ps1` works everywhere.** `LauncherConfig.custom.ps1` per engine + `SOLUTIONS/SecurityInsight/CUSTOMDATA/SecurityInsight.custom.ps1` solution-wide now override defaults on every engine × flavour combination, not just the 5 engines that already had the modern loader (RiskAnalysis, IdentityAssetsCollect, Build_Tier, Step1, Step4).
  - **Consistency win #2: `DATA\LOGS\config-*.log` fires everywhere.** The layer-provenance snapshot (v2.1.143) now writes for every launcher invocation across every engine × flavour.
  - **Consistency win #3: Same launcher flow for community + internal.** The ONLY difference between the two is the content of `SOLUTIONS/PlatformConfiguration/CUSTOMDATA/platform-defaults.ps1` (Layer 2) — populated for internal deployments, empty/absent for community. Launcher code is identical.
- 🔧 **Strip stale `$SpnTenantId is required (set it in LauncherConfig.ps1)` guard** from the community-vm templates — `Initialize-LauncherConfig -RequireCustom` now owns the "file missing / required values absent" error path with a better message.

### v2.1.144 — CriticalAssetTagging Locked/Custom merge by `<stem>--SI` (tier is overridable data)

- 🧰 **Merge key is now the stem + `--SI` suffix**, not the full `AssetTagName`. Identity = asset class ("which rule is this"), the `--tier<N>--` segment is treated as overridable data. Customer can re-tier a shipped rule by dropping a Custom entry with the same stem and a different tier integer — no need to copy the full Locked query or disable the Locked rule.
  - **Example:** Locked ships `BackupOperators--tier1--SI`; customer drops `BackupOperators--tier0--SI` in Custom.yaml; effective run tags Backup Operators at tier 0. Custom's full rule (query included) wins.
- ⚠️ **Strict naming required.** Every `AssetTagName` must match `<stem>--tier<N>--SI`. Malformed names throw at YAML merge time with a clear error pointing at the offending entry and the source file (Locked.yaml vs Custom.yaml). There is intentionally no full-string fallback — simpler semantics, no ambiguous collisions.
- 📚 **README § 6.7 new subsection** documents the convention + stem-based merge + two use-case recipes: (1) promote an asset class from Tier 1 to Tier 0, (2) force a full re-tag by dropping the trailing delta filter from a Custom override query.

### v2.1.143 — Per-run `config-*.log` snapshot in `DATA\LOGS\`

- 🆕 **Every launcher invocation now writes a config snapshot to `<InstallPath>\DATA\LOGS\config-<Engine>-yyyyMMdd-HHmmss-<Device>.log`.** Captures the effective config the engine ran with, plus full provenance per variable so you can tell which layer owns each value.
  - **Layer provenance** — `Initialize-LauncherConfig.ps1` snapshots all SI-relevant `$global:*` variables BEFORE each layer loads and diffs AFTER, attributing every new/changed value to the layer that set it: *Layer 0 shared-defaults / Layer 1 LauncherConfig.defaults / Layer 2 platform-defaults (internal) / Layer 3 SecurityInsight.custom / Layer 4 LauncherConfig.custom / Layer 4b derived*.
  - **Secret redaction** — any variable whose NAME matches `Secret|Password|Pwd|ApiKey|Api_Key|AccessKey|AccessSecret|Token|ClientSecret|Cert(ificate)?Thumbprint` is logged as `[REDACTED (len=N)]` so presence can still be verified without leaking the value. `PSCredential` and `SecureString` values are redacted too.
  - **7-day retention** — `config-*.log` files older than 7 days are pruned from `DATA\LOGS\` at the end of each run.
- 🧰 **Use case**: when a customer reports "my Identity run picked the wrong DCE", point at their `DATA\LOGS\config-IdentityAssetsCollect*-<latest>.log` and read the layer provenance section — the wrong value will be listed with `[from: Layer 2 - platform-defaults (internal)]` or wherever it came from, so you fix the right file on the first try.

### v2.1.142 — `TraceName` gets a trailing `--SI` source tag

- 🧰 **TraceName format now `<ConfigurationName>--<SecuritySeverity>--<CriticalityTierLevel>--SI`** (was the same without the `--SI` suffix). Matches the `--SI` convention already used on Defender asset tags (e.g. `DomainControllerDNS--tier0--SI`), so aggregators, SIEMs, and Power BI can filter findings by source system at the TraceName level instead of needing a separate column lookup.
- ⚠️ **`TraceID` values will change on next run** — SHA-256 is deterministic over the new string, so every finding gets a new 16-hex ID. Historical group-by-TraceID queries for the same finding pre-v2.1.142 will see a discontinuity at the run boundary. This is the expected behaviour of the rebrand, not a bug.

### v2.1.141 — § 4.3 / 4.4 / 4.5 byte-for-byte resync from authoritative source README

- 📚 **Sections 4.3 (Identity), 4.4 (Endpoint), 4.5 (Azure) now mirror the upstream catalog `c:\tmp\README.md` byte-for-byte** (verified row-MD5 + grep diff). Source format preserved verbatim — single-row 2-column markdown tables with inline `<br />` separators between sub-categories (Entra ID Roles / Application Permissions / Azure Built-in Roles / Azure Permissions / AD / AD Built-in Groups / AD Permissions / Accounts for Identity; Server Roles / Management / Infrastructure / Hypervisor / Network Equipment / IoT/OT / Client Devices for Endpoint; Compute / Storage / Identity & Access / Networking / Management & Governance / Hypervisor & Fabric for Azure). Includes the upstream disclaimer about classifications being a "strategic prioritization framework, not a definitive or exhaustive measure of asset risk".

### v2.1.140 — § 4.1–4.5 resync to verbatim MEM26 PDF text

- 📚 **§ 4.1 Severity definitions** rewritten with the verbatim PDF page-27 attack-impact text (was paraphrased / abbreviated).
- 📚 **§ 4.2 Criticality definitions** rewritten with the verbatim PDF page-30 attack-impact text per tier — full Kerberos-ticket-forging / MFA-reset / SharePoint exfil / phishing-foothold descriptions, not the one-line summaries.
- 📚 **§ 4.3 Asset classification: Identity** restored to the full PDF page 35–39 detail across Tier-0 → Tier-3, with the proper sub-groupings (Cloud — Entra ID Roles, Cloud — Entra ID Services, Application Permissions (Graph/API), Azure Built-in Roles, Azure Permissions, AD, AD Built-in Groups, AD Permissions, Accounts).
- 📚 **§ 4.4 Asset classification: Endpoint** rebuilt from PDF page 40–43 — was a 4-row summary table, now a Tier-0 → Tier-3 detail set with the same shape as 4.3 (Core Identity Infrastructure / Privileged Management / Network & OT, Servers & Services, etc.).
- 📚 **§ 4.5 Asset classification: Azure** rebuilt from PDF page 44–47 — was a 4-row summary table, now a Tier-0 → Tier-3 detail set (Azure Built-in Roles per scope, Identity & Control Plane, Workload Identities & Permissions, Critical Azure Resources).

### v2.1.139 — README polish: Power BI "Beta" + v2.1.113/114/116/122/125/129 highlights

- 📚 **Power BI status flipped from "In development" to "Beta".** The Step 4 deploy engine, `.pbix` REST API upload, `$global:SendToPowerBI` per-run refresh, Setup Configurator tab, and prereq doc have all shipped. Matches the BETA badge in the Setup Configurator UI.
- 📚 **`§ 5 What's New` table gained three rows** covering the v2.1.113 → v2.1.129 arc that previously only lived in this curated log: single canonical PowerShell module set + `-Scope AllUsers` default (v2.1.113/114/122/125), daily auto-refresh scheduled task (v2.1.116), and sub+RG-scoped DCE/DCR cache filter (v2.1.129).
- 📚 **§ 4.1 Severity definitions** rewritten with the verbatim PDF page-27 attack-impact text (was paraphrased / abbreviated).
- 📚 **§ 4.2 Criticality definitions** rewritten with the verbatim PDF page-30 attack-impact text per tier — full Kerberos-ticket-forging / MFA-reset / SharePoint exfil / phishing-foothold descriptions, not the one-line summaries.
- 📚 **§ 4.3 Asset classification: Identity** restored to the full PDF page 35–39 detail across Tier-0 → Tier-3, with the proper sub-groupings (Cloud — Entra ID Roles, Cloud — Entra ID Services, Application Permissions (Graph/API), Azure Built-in Roles, Azure Permissions, AD, AD Built-in Groups, AD Permissions, Accounts).
- 📚 **§ 4.4 Asset classification: Endpoint** rebuilt from PDF page 40–43 — was a 4-row summary table, now a Tier-0 → Tier-3 detail set with the same shape as 4.3 (Core Identity Infrastructure / Privileged Management / Network & OT, Servers & Services, etc.).
- 📚 **§ 4.5 Asset classification: Azure** rebuilt from PDF page 44–47 — was a 4-row summary table, now a Tier-0 → Tier-3 detail set (Azure Built-in Roles per scope, Identity & Control Plane, Workload Identities & Permissions, Critical Azure Resources).

### v2.1.138 — Silence duplicate `module 'X' v... present` lines from launcher templates

- 🧰 **Launcher templates no longer announce every module they probe.** Every `launcher.*.template.ps1` (32 files across 8 engines × 4 flavours) had its own inline `Test-LauncherModule` helper that logged `[OK] module '<name>' v<ver> present` for each of the ~8 auth-relevant modules it checked. The engine's centralised `Ensure-SecurityInsightModules` then printed the same list a second time as `[MODULE] probing X ...` / `[MODULE] X v... present`, so every run emitted two parallel module-check blocks. Launcher helper now returns `$true` silently on success; capability detection (`$haveKv`, `$haveMg`) still works; install + failure messages still log. End result: one visible module-check block per run, from the engine, with the canonical `[MODULE]` prefix.

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

