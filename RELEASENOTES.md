# Release notes for SecurityInsight

## v2.2.14

Latest 30 commits touching SOLUTIONS/SecurityInsight/ in the upstream monorepo monorepo:

- release: SecurityInsight v2.2.14 - DCR-cache retry + Pre-Publish Gate exception (cc579806)
- release: SecurityInsight v2.2.13 - ship privilege-tier-catalog + 10-step docs refresh (105614a7)
- release: SecurityInsight v2.2.12 - PublicIP tolerate missing Profile tables (acfc2a9e)
- release: SecurityInsight v2.2.11 - PublicIP surface KQL error body (73b03856)
- release: SecurityInsight v2.2.10 - PublicIP Set-AzContext + Use-SIAzContext helper (1dc6fac4)
- release: SecurityInsight v2.2.9 - fix RA Summary template name (dfd2e677)
- release: SecurityInsight v2.2.8 - public repo .gitignore (bfda9aa4)
- release: SecurityInsight v2.2.7 - Shodan key name unification (2e0bae79)
- release: SecurityInsight v2.2.6 - PTC opt-in via -PrivilegeTierClassifier (62524773)
- release: SecurityInsight v2.2.5 - Run-AllEngines public + race fix + Identity error (f0f482d6)
- release: SecurityInsight v2.2.4 — silence git-stderr noise in demo orchestrator (3953a88d)
- release: SecurityInsight v2.2.3 — gate fixes + demo orchestrator (feaaab0c)
- release: SecurityInsight v2.2.2 — README cosmetic fixes (082b8577)
- release: SecurityInsight v2.2.1 — patch (publish-pipeline + Reconcile fixes) (dcec31e9)
- fix(reconcile): skip Write-SIStageShard when records array is empty (39b7cdc8)
- SI v2.2.0 stable: flatten v2.2/ to root, drop v2.1 layout, audit-pass RA fixes (536e1405)
- ci(publish): per-channel sourceRef + README regression guard (43b6e88c)
- docs(SI README): add 'New release v2.2 coming very soon !' teaser callout (9b283fcf)
- feat+fix(SI v2.2): preview.196 — anne-tier fix, native logon rule, cross-merge guard, Match→CmdbMatch, Summary↔Detailed parity, YAML cleanup (b50f9220)
- fix(SI v2.2): preview.194 — routing: skip reports needing ExposureGraph + SI_*_Profile_CL when EG isn't reachable from LA (5d77492e)
- fix(SI v2.2): preview.193 — wrap 75 more bare tostring(<col>) refs in column_ifexists (9b7cd01c)
- fix(SI v2.2): preview.192 — wrap value-side tostring(<col>) in column_ifexists so case() Category/Subcategory parses when source column is missing (133fd01c)
- fix(SI v2.2): preview.191 — drop CrossEngine completely + fix Subcategory undefined (3fc1ade1)
- feat(SI v2.2): preview.190 — restore Category/Subcategory from legacy v2.1 (106 reports), drop CrossEngine, simpler risk-analysis.schema.json with Impact-by-Category map (440ec891)
- fix(SI v2.2): preview.189 — engine-level row dedup by (ConfigurationName, ConfigurationId) collapses 50x mv-expand+join inflation (d89afb9a)
- fix(SI v2.2): preview.188 — Discover layout: drop NoNewline progress that glued helper output, normalize [perms] indent (93008ef5)
- feat(SI v2.2): preview.187 — new canonical column Issues_Details (array of distinct ConfigurationName(s) per report; LA dynamic, Excel joined) (214ddeb2)
- feat(SI v2.2): preview.186 — ImpactedAssets is an array of distinct AssetName(s) per report (LA dynamic, Excel comma-joined) (3de390a7)
- docs(SI v2.2): preview.185 — TraceName composition doc fix (legacy engine, unchanged) (87931749)
- feat(SI v2.2): preview.184 — Category/Subcategory: 242 reports rewritten to platform-pull (10 CVE keep static); Subcategory case normalized (9309b74f)

---

# Release notes — SecurityInsight v2.2

> **Curated changelog**. The publish workflow auto-prepends the last 30 commits from the upstream monorepo as a raw activity log; this file is the human-friendly narrative on top.

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

