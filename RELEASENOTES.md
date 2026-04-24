# Release notes for SecurityInsight

## v2.1.213

Latest 30 commits touching SOLUTIONS/SecurityInsight/ in the upstream monorepo monorepo:

- feat(SI Setup Configurator): strip to wizard-only (remove Step1/Step2/Step3/Step4/Engines tabs) (1268dc30)
- fix(SI Setup Configurator wizard): conditional-visibility (hidden-attr clobber) + add missing cert display-name input (d02a08b5)
- feat(SI Setup Configurator): 3 novice-friendly tweaks (Save-direct + install one-liner + Finish callout) (08d00d15)
- fix(SI Step3 + InitialDeployment): auto-capture OpenAI values into customdata (no copy/paste) (c70f0797)
- feat(SI): InitialDeployment_Latest_Version_SecurityInsight.ps1 -- single-file orchestrator with built-in interactive setup wizard (cd351d7e)
- feat(SI Setup Configurator): Initial Setup Wizard -- 5-step all-in-one flow emitting CUSTOMDATA/SecurityInsight.custom.ps1 (4c02e63d)
- feat(SI sample): expand SecurityInsight.custom.sample.ps1 for the upcoming Initial Setup Wizard (4b637522)
- fix(SI RiskAnalysis Excel): defensive XLSX-safe sanitizer to kill the 'Repaired Records: sharedStrings.xml' open warning (3fab7506)
- feat(SI YAML): Identity_AnyUser_NoMFA_Summary excludes external/B2B + fix typo in PrivilegedUser NoMFA Detailed scope (ba90f139)
- fix(SI RiskAnalysis): drop @() wrap at the pure-LA Invoke-LogAnalyticsKqlQuery caller (02beb56d)
- fix(SI _lib Initialize-LauncherConfig): snapshot params before dot-sourcing layer files (8f84a82b)
- fix(SI RiskAnalysis): pure-LA route via _SIDirectRows marker, bypassing the broken broadcast + ConvertTo-PSObjectDeep path (30715aa8)
- fix(SI RiskAnalysis): targeted 413 message + sign-in-table classifier hint (c5d303e2)
- feat(SI YAML): 4 new locked NoMFA reports for Tier 2 (PowerUser) + Tier 3 (RegularUser), Summary + Detailed each (5174d712)
- fix(SI RiskAnalysis): strip KQL string literals before XDR-detection regex + fix size-warning format-string (86f5a986)
- fix(SI RiskAnalysis launchers): AutoBucketMax layered-config + widen ValidateRange to 2048 (ddff8ebf)
- chore(SI RiskAnalysis defaults): WriteJsonOutput=$false + AutoBucketMax=1024 (585da7d4)
- fix(SI RiskAnalysis): route pure-LA queries direct to Log Analytics, avoiding nginx 413 on the let-block bridge (240cbc19)
- docs(SI README): add Sec 3.5.4 Defender XDR licensing & onboarding requirements (312c404c)
- feat(SI RiskAnalysis): no-retry on schema errors + Defender service classification (aa668516)
- fix(SI IdentityAssetsCollect): bulk userRegistrationDetails MFA fetch + log silent catch (fb4baabe)
- feat(SI RiskAnalysis): transparent SI_IdentityAssets_CL bridge for workspaces without Sentinel data lake mirroring (3c18481c)
- chore(SI IdentityAssets defaults): drop WorkspaceResourceId + ExportDestination pre-declarations (333e09df)
- fix(SI Step3): include \$global:BuildSummaryByAI = \$true in end-of-run paste-block + sample.ps1 cross-reference (22a20218)
- fix(SI Step3 OpenAI): ship the missing LauncherConfig.defaults.ps1 (1dbf4209)
- docs(SI): replace stale 'LauncherConfig.ps1' user-facing references with 'LauncherConfig.custom.ps1' (37 hits / 19 files) (0ae16e21)
- fix(SI Step1 + Step4 launchers): auth fields fall back to runtime \$global:Spn* when Step-specific names aren't set (33f757a2)
- fix(SI Step1 Permissions): drop device-code fallback + add -Force to clear stale Az context on Interactive sign-in (ba36ae3f)
- docs(SI _samples): refresh Sample - RiskAnalysis_{Summary,Detailed}_Bucket.xlsx from a recent run (1d68d1f5)
- fix(SI Layer 4 defaults): 49 more unconditional \$global assignments converted to conditional (IdentityAssets / Step1 / Step2 / Step4) (07c37a0a)

---

## Curated highlights

The auto-generated commit log above tells you **what** changed in code. This section tells you **why you care** — grouped by release, latest first, with the customer-visible impact of each bump.

Legend: 🆕 new feature · 🔧 fix · 📚 docs · 🧰 infrastructure · ⚠️ breaking (none so far in v2.1.x)

---

### v2.1.213 — Setup Configurator: strip to wizard-only (remove Step1/Step2/Step3/Step4/Engines tabs)

- 🧰 **Customer feedback:** the 5 per-engine tabs alongside the wizard were confusing novices — "am I supposed to fill out all of them?" The wizard alone generates the solution-wide `CUSTOMDATA/SecurityInsight.custom.ps1` that every engine inherits from; the per-engine Layer-5 `LauncherConfig.custom.ps1` tabs were advanced tuning that most customers never needed. Removing them.
- 🗑️ **Deleted** from `TOOLS/SetupConfigurator/index.html`:
  - The 6-tab navigation bar at the top
  - All 5 per-engine `<section>` blocks (`tab-step1` / `tab-step2` / `tab-step3` / `tab-step5` / `tab-engines`)
  - Supporting JS: `buildStep1` / `buildStep2` / `buildStep3` / `buildStep5` / `buildEngines` / `syncAuthVisibility` functions, tab-click handlers, multi-tab dispatch in `render()`, multi-target `targetPaths` / `launcherCmds` maps
- 🧰 **Result:** page drops from 1565 → 778 lines. Single-purpose wizard. Header renamed from *"Setup Configurator"* to *"Initial Setup Wizard"*. Subtitle explicitly directs the user: *"Answer 5 short questions → save the generated `SecurityInsight.custom.ps1` into `CUSTOMDATA/` → run `InitialDeployment_Latest_Version_SecurityInsight.ps1` from your install root. Done."*
- 🧰 **No behaviour change** for customers who were already using the wizard — same 5-step flow, same output, same save buttons (`💾 Save directly` / `⬇ Download` / `📋 Copy to clipboard` / `📋 Copy install one-liner`). Only the other tabs are gone.
- 🧰 **Advanced per-engine tuning** is still available — customers can still edit `LAUNCHERS/<engine>/LauncherConfig.custom.ps1` files by hand when they need engine-specific overrides. Just no longer surfaced in the setup tool (which is now strictly first-install).

### v2.1.212 — Setup Configurator wizard: fix conditional-visibility (hidden-attribute clobber) + add missing certificate display-name input

- 🔧 **Bug — wizard sub-blocks never appeared.** Customer reported: picking "Create new SPN" didn't show the display-name field; picking "SPN+Certificate (existing)" didn't show the thumbprint input; picking "SPN+Certificate (new)" had no name input at all; toggling "Send mail = Yes" didn't reveal the SMTP fields; toggling "Upload to storage = Yes" didn't reveal the destination input. Root cause: the wizard sub-blocks have the HTML `hidden` attribute set on initial render (so the page paints cleanly before JS runs), but my `syncWizardVisibility()` was using `toggleClass()` which only sets `style.display`. **`style.display = ''` does NOT override the `hidden` attribute** (per HTML spec, `hidden` always wins). Result: every sub-block stayed invisible regardless of radio selection.
- 🔧 **Fix.** New `setWizVisible(selector, show)` helper that manipulates `el.hidden` directly. Replaced every `toggleClass` call in `syncWizardVisibility` with the new helper. All conditional fields now appear/disappear correctly when the user clicks the corresponding radio.
- 🆕 **Added missing input — Certificate display name (new cert path).** Picking SPN+Certificate → "Generate new self-signed during deployment" now shows a `Certificate display name` field (default `cert-securityinsight`). The wizard emits `$global:OnboardValidate_CertificateDisplayName = '...'`, and the orchestrator's Phase 1 will use it to name the self-signed cert it generates in `CurrentUser\My`.
- 🧰 **Other inputs verified now-visible** after the visibility fix: SPN display name (new SPN path), tenant ID (cert + MI paths), all mail fields (From / To / SMTP server / port / auth user / password / per-mode routing), upload destination (Azure blob URL / UNC path) + JSON sibling toggle.

### v2.1.211 — Setup Configurator wizard: 3 novice-friendly tweaks (Save-direct + install one-liner + prominent Finish callout)

- 🆕 **(a) Save directly to CUSTOMDATA** (Chrome / Edge). New `💾 Save directly` button uses the **File System Access API** (`window.showSaveFilePicker`) — opens a Save-As dialog so the user can drop the file straight into `CUSTOMDATA/` with the proper `.ps1` extension in one click. **No download → rename → move dance.** Browsers without the API (Firefox / Safari) silently fall back to the `.txt` download.
- 🆕 **(b) Copy install one-liner.** New `📋 Copy install one-liner` button. Copies a single PowerShell command that **moves the just-downloaded `SecurityInsight.custom.ps1.txt` from `Downloads\` into `CUSTOMDATA\`, renames it to `.ps1`, and unblocks Mark-of-the-Web** in one shot. User pastes into PS, hits Enter, done. Works for engine tabs too (auto-targets the right LAUNCHERS path).
  ```powershell
  Move-Item -Path "$env:USERPROFILE\Downloads\SecurityInsight.custom.ps1.txt" -Destination ".\CUSTOMDATA\SecurityInsight.custom.ps1" -Force
  Unblock-File -LiteralPath ".\CUSTOMDATA\SecurityInsight.custom.ps1"
  ```
- 🆕 **(c) Prominent Finish callout.** Clicking the wizard's `✅ Finish & Generate` button now flashes a thick green border + brighter background on the "Next step — run the launcher" panel, scrolls it into view, and shows a 8-second toast: *"Configuration ready. Save the file (button above) + run InitialDeployment (button below)."* No more guessing what to do next.
- 🧰 **Button order in the preview bar** reorganised so the easiest path is leftmost: `💾 Save directly` (primary) → `⬇ Download` → `📋 Copy to clipboard` → `📋 Copy install one-liner`. Updated hint text walks novices through each option's tradeoff.
- 🧰 **End-to-end novice flow now (after this ship):**
  1. Open `TOOLS/SetupConfigurator/index.html` in Chrome/Edge
  2. Wizard tab is the default. Answer 5 prompts.
  3. Click `✅ Finish & Generate` → panel below highlights → click `💾 Save directly` → pick `CUSTOMDATA/` folder → done.
  4. Click `📋 Copy run-command to clipboard` → paste into elevated PS → Enter.
  5. Sign in once interactively as Global Admin → orchestrator does everything else (creates SPN, secret, LA, OpenAI, runs first reports).
  6. Total interactions: 5 wizard answers + 2 button clicks + 1 sign-in. No filename rename, no manual paste of secrets.

### v2.1.210 — Auto-capture Step3's OpenAI values into customdata (no copy/paste for novice users)

- 🔧 **Customer concern**: novice users running `InitialDeployment` had to copy/paste 5 `OpenAI_*` lines from Step3's console output into `CUSTOMDATA/SecurityInsight.custom.ps1` after Phase 3. Easy to miss; defeats the "single-file all-in-one" promise.
- 🔧 **Step3 fix.** Step3 already builds `$AI_apiKey` / `$AI_endpoint` / `$AI_deployment` / `$AI_apiVersion` as local vars then prints them as a paste-block. Now also exports them as `$global:OpenAI_apiKey` / `_endpoint` / `_deployment` / `_apiVersion` / `_MaxTokensPerRequest` (16384 default) at the very end of the script. Plus `$global:BuildSummaryByAI = $true`. The console paste-block stays — anyone running Step3 standalone still gets it — but the orchestrator now has a programmatic path.
- 🔧 **InitialDeployment fix.** Phase 3 now reads `$global:OpenAI_*` after Step3 returns and writes each value into `CUSTOMDATA/SecurityInsight.custom.ps1` via the existing `Update-CustomData` helper (idempotent in-place edit + `.before-deploy.bak` backup). Status reports `OK (auto-captured)` with the captured count.
- 🧰 **Result.** A novice running `.\InitialDeployment_Latest_Version_SecurityInsight.ps1` for the first time now ends up with a complete `CUSTOMDATA/SecurityInsight.custom.ps1` after one run — every value the engines need (SPN clientId + 2-yr secret, workspace resource ID, DCE ingestion URI, OpenAI key/endpoint/deployment/apiVersion) auto-populated. No manual edits required.
- 🧰 **Backwards-compatible.** If Step3 is older than v2.1.210 (caches in `_install/SI/SCRIPTS/` not yet updated), Phase 3 logs `PARTIAL (captured=0/5)` instead of crashing, and the user sees the old paste-instruction. Re-running InstallUpdate fixes it.

### v2.1.209 — `InitialDeployment_Latest_Version_SecurityInsight.ps1` — single-file orchestrator with built-in interactive setup wizard

- 🆕 **One script does everything.** New file at the SI install root: `InitialDeployment_Latest_Version_SecurityInsight.ps1`. First run: a built-in TUI wizard asks ~5 yes/no questions, then signs the admin in interactively, creates the SPN + 2-year secret named `secret` + grants tenant-root + per-subscription Owner roles, provisions Log Analytics infrastructure, optionally provisions OpenAI, runs the IdentityAssetsCollect engine to populate `SI_IdentityAssets_CL`, runs RiskAnalysis to validate end-to-end, and (optionally) deploys the Power BI dashboard. Re-run any time → idempotent validation pass.
- 🧰 **Wizard prompts (TUI, ~5 questions, mostly Enter-to-accept-defaults):**
  1. **Auth method:** SPN+secret (auto-create) [default] / SPN+secret (existing) / Managed Identity
  2. **Log Analytics subscription ID** (required GUID)
  3. **Enable AI summary?** [Y/n] — toggles `$global:BuildSummaryByAI`
  4. **Send mail?** [y/N] — if Yes, From / To / SMTP server+port / auth user+pass
  5. **Upload reports?** [y/N] — if Yes, blob URL or UNC path
- 🧰 **Interactive sign-in only on first run.** When `$global:SpnClientId` + `$global:SpnClientSecret` are missing from `CUSTOMDATA/SecurityInsight.custom.ps1`, Phase 1 calls `Connect-AzAccount` + `Connect-MgGraph` interactively (browser sign-in by Global Admin / Privileged Role Admin). The created SPN + secret are written back into `SecurityInsight.custom.ps1` so subsequent runs use SPN auth (non-interactive). `-ForceInteractive` flag triggers re-sign-in if the secret was rotated externally.
- 🧰 **Auto-grant Owner on the LA + OpenAI subscriptions.** During Phase 1's interactive admin session — the only window when a human with elevated rights is available — the script grants the new SPN `Owner` on `$global:SubscriptionId` (LA) and `$global:Step3_SubscriptionId` (OpenAI, if different). Without this, subsequent SPN-authenticated runs can't auto-create workspaces / DCEs / DCRs / OpenAI accounts on the target subscriptions. Idempotent: skips if role already assigned. Logs a clear hint with the manual grant command if the signed-in admin lacks Owner / UAA on a target subscription.
- 🧰 **Tenant-root grants** (Reader + Tag Contributor at the tenant-root MG) also happen in Phase 1 — same pattern as the existing Step1 engine.
- 🧰 **6 phases, each idempotent + logged:**
  - **1. SPN+Permissions** — interactive on first run, validate-only on re-run
  - **2. LA infrastructure** — workspace + DCE + DCR + DCE/DCR resource groups + RBAC
  - **3. Azure OpenAI** — only if `$global:BuildSummaryByAI=$true`; calls existing Step3 engine
  - **4. IdentityAssetsCollect** — populates `SI_IdentityAssets_CL`
  - **5. RiskAnalysis** — first end-to-end report run (Summary mode default)
  - **6. Power BI** — only if `$global:SendToPowerBI=$true`; calls Step4 engine
- 🧰 **Write-back.** Auto-generated SPN clientId / secret / OpenAI keys / DCE ingestion URI / workspace resource ID get persisted into `CUSTOMDATA/SecurityInsight.custom.ps1` automatically (with backup `.before-deploy.bak`). After a single first run, the file is complete — customer never has to copy/paste console output.
- 🧰 **Final summary table** — Phase / Status (OK / SKIP / FAIL) / Seconds / Detail. Non-zero exit code if any critical phase failed.
- 🧰 **Flags:** `-Phase Spn,LA` (run only specific phases), `-ForceInteractive` (re-sign-in for SPN repair), `-ReconfigureWizard` (re-prompt the wizard even when customdata exists), `-SkipWriteBack` (don't edit customdata file).
- 🧰 **Fully complements the v2.1.208 HTML wizard** — customers can use either path. HTML wizard for visual planning + the orchestrator picks the file up; or just run the orchestrator and answer 5 prompts at the command line.

### v2.1.208 — Setup Configurator: new `🚀 Initial Setup Wizard` tab (now the default) — configure everything in ONE flow, emits `CUSTOMDATA/SecurityInsight.custom.ps1`

- 🆕 **New default-active tab `🚀 Initial Setup Wizard`** at `TOOLS/SetupConfigurator/index.html`. Five-step flow with a progress pill stepper, conditional-visibility fields, and a live preview that updates as you type. Output target: **`CUSTOMDATA/SecurityInsight.custom.ps1`** (the solution-wide Layer 3 file — every engine inherits from here) — not the per-engine Layer 5 files. The existing per-engine tabs stay as `Step 1 — Permissions` / `Step 2 — Log Analytics` / `Step 3 — Azure OpenAI` / `Step 4 — Power BI` / `Ingestion engines` for advanced per-engine tuning.
- 🧰 **Step 1 — Authentication.** Pick `SPN + secret` / `SPN + certificate` / `Managed Identity`. For SPN or cert you choose **"use existing" vs "create new during deployment"**. Existing → the wizard collects tenant / clientId / secret or thumbprint directly. New → the wizard collects just the SPN display name (or nothing for cert), and v2.1.209's orchestrator provisions the SPN/cert + writes the resulting values back during Step 1 of the deployment.
- 🧰 **Step 2 — Log Analytics.** Single required field: subscription ID. Optional workspace name override. The orchestrator auto-creates the workspace + DCE + DCR if they don't exist.
- 🧰 **Step 3 — Azure OpenAI.** Radio toggle (Yes default / Skip). When enabled, emits `$global:BuildSummaryByAI = $true` + optional separate subscription for OpenAI. The 5 `OpenAI_*` values get filled in by the orchestrator's Step 3 run.
- 🧰 **Step 4 — Mail.** Radio toggle (Yes / No default). When enabled: From, fallback To, SMTP server/port, auth method (Authenticated / Anonymous), per-report routing (Summary + Detailed, each with their own enable toggle + recipient list).
- 🧰 **Step 5 — Output.** Radio toggle for storage upload. When enabled: storage type (Azure blob / UNC), destination path, JSON sibling yes/no.
- 🧰 **Three save options** in the preview panel (same buttons existing tabs use, now smart about filename):
  - **`📋 Copy to clipboard`** — paste into your editor, save as `SecurityInsight.custom.ps1` in `CUSTOMDATA/`
  - **`⬇ Download`** — lands as `SecurityInsight.custom.ps1.txt` in Downloads (`.txt` suffix because Windows MOTW blocks opening browser-downloaded `.ps1`; rename after saving)
  - **`📋 Copy run-command`** — copies `.\InitialDeployment_Latest_Version_SecurityInsight.ps1` so you can launch the orchestrator right after saving the file
- 🧰 **Conditional visibility** driven by `syncWizardVisibility()` — picking "SPN + Certificate" hides the secret fields, picking "Existing SPN" vs "Create new" swaps the required inputs, toggling mail/upload/OpenAI on/off hides their entire sub-sections. Stepper pills light green (`done`) behind you and blue (`active`) on the current step.
- 🧰 **Preview-panel smart labels.** Wizard active → header reads `Generated SecurityInsight.custom.ps1`, download filename + the "Next step — run the launcher" bubble both switch to the CUSTOMDATA path + the orchestrator command. Switching to an engine tab flips them back.
- 🧰 **No JavaScript dependencies / no server round-trips** — same in-browser principle as before. All processing stays on the client. The orchestrator script that consumes this output file ships in v2.1.209 (next).

### v2.1.207 — `CUSTOMDATA/SecurityInsight.custom.sample.ps1` refreshed with every wizard-relevant global (prep for the new Initial Setup Wizard)

- 🧰 **Added `$global:BuildSummaryByAI = $true`** to section 2 (Azure OpenAI) with an explicit comment that it's the MASTER ON/OFF toggle. Without it the engine silently skips the AI summary even when the 5 `OpenAI_*` values are perfect — this was a recurring customer confusion.
- 🧰 **Expanded section 4 (DCR INGESTION TARGETS)** with `$global:SendToLogAnalytics`, `$global:BatchSize`, `$global:TableName` — the missing master-toggle + IdentityAssetsCollect tuning knobs.
- 🧰 **Overhauled section 8 (RiskAnalysis)** — previously AF-only, now covers the full per-mode config surface: `RiskAnalysis_Summary_Override` / `_Detailed_Override`, `ReportTemplate_Default_Summary` / `_Detailed`, both community-mode (`RiskAnalysis_Summary_SendMail` / `_To`) and AF-mode (`Mail_SecurityInsight_Summary_SendMail` / `_To`) mail routing, JSON sibling + blob upload (`WriteJsonOutput`, `ExportDestination`), and Power BI refresh (`SendToPowerBI`, `PowerBI_WorkspaceName`, `PowerBI_DatasetName`).
- 🧰 **Every line still commented out by default** — the sample is a reference-pattern + checklist, not an active config. Customer copies it to `SecurityInsight.custom.ps1` (gitignored) and uncomments what they need.
- 📚 **Lays the foundation for v2.1.208's Initial Setup Wizard** — the wizard emits `SecurityInsight.custom.ps1` into this folder, and the sample is the canonical reference for what every wizard-emitted global means and where it goes.

### v2.1.206 — RiskAnalysis Excel: defensive XLSX-safe sanitizer (kills the `Repaired Records: String properties from sharedStrings.xml` Excel-open warning)

- 🔧 **Bug — Excel pops `Repaired Records: String properties from /xl/sharedStrings.xml` warning** when opening `RiskAnalysis_*.xlsx`. Customer's Excel still recovers all rows, but the dialog is noisy and shakes confidence in the data. Cause: an XML-illegal control character (0x00 NUL, 0x0B vertical tab, 0x0C form feed, 0x07 BEL, 0x1B ESC, 0x7F DEL, etc.) or a lone UTF-16 surrogate half slipped into a cell value -- typically via a KQL `extract()` result, a `CSA` JSON blob, a `TierSources` payload, or pasted-in display name. `ImportExcel` writes the raw value; Excel's strict validator on file-open rejects the entry per XML 1.0 spec.
- 🔧 **Fix.** New `ConvertTo-XlsxSafeString` helper (top of engine, near `Reset-ExcelOutput`). Strips:
  - Control chars `0x00-0x1F` **except** TAB (`0x09`), LF (`0x0A`), CR (`0x0D`) which XML 1.0 explicitly allows
  - DEL `0x7F`
  - Lone high surrogates (`U+D800..U+DBFF` not followed by a low surrogate)
  - Lone low surrogates (`U+DC00..U+DFFF` not preceded by a high surrogate)
  - **Preserves** valid UTF-8 (incl. extended Latin) AND valid surrogate pairs (e.g. emoji `U+1F600` round-trips correctly)
- 🧰 **Applied at both Export-Excel callsites:** `Export-Worksheet` (the main per-report exporter -- runs the sanitizer over every string property of every row before piping to `Export-Excel`) and `Export-AISummaryWorksheet` (the AI summary sheet -- sanitizes each line of the OpenAI text). Non-string property values pass through untouched (datetimes, numbers, bools).
- 🧰 **Verified end-to-end** with a PS 5.1 test that wrote a row containing every flavour of bad char + emoji + UTF-8 to a real .xlsx, then (a) round-tripped via `Import-Excel` and (b) extracted `xl/sharedStrings.xml` from the .xlsx zip and parsed it as XML. Both paths clean. Test deleted after passing.
- 🧰 **Zero performance impact** in the common case -- sanitizer is a no-op for any string with no bad chars (the regex `[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]` matches nothing on a clean string and returns immediately).

### v2.1.205 — Locked YAML: `Identity_AnyUser_NoMFA_Summary` excludes external / B2B + typo fix in PrivilegedUser NoMFA Detailed scope

- 🧰 **`Identity_AnyUser_NoMFA_Summary` — added `| where IsExternal == false`** to the main KQL filter chain. External / B2B users typically register MFA in their HOME tenant, not the resource tenant; including them inflated the "users missing MFA" count with accounts that aren't actually the reporting tenant's responsibility. The dedicated `Identity_StaleGuest_NoLogin90Days_*` reports already cover guest-specific hygiene separately.
- 🔧 **Typo fix — `Identity_PrivilegedUser_NoMFA_Detailed` CriticalityTierLevelScope had `"Low - tier 32"`** (stray trailing `2`) instead of `"Low - tier 3"`. The engine's filter uses an exact-match (case-insensitive) compare, so Tier-3 findings under this report would never match the scope and get silently dropped. Fixed to the canonical `"Low - tier 3"` value used everywhere else in the catalog.

### v2.1.204 — RiskAnalysis pure-LA route: drop the `@()` wrap around the comma-protected return (THE actual cause of the SyncRoot wrap and System.Array properties leaking into rows)

- 🔧 **Bug — pure-LA queries STILL wrote rows wrapped in System.Array** even after v2.1.202's `_SIDirectRows` marker bypass. Customer dump showed `$ResultAll`, `$ResultFiltered`, `$RiskScoreArray` all containing a single object whose surface was `System.Array`'s .NET properties (`Count`, `Length`, `LongLength`, `Rank`, `IsFixedSize`, `IsReadOnly`, `IsSynchronized`, `SyncRoot`) plus engine-stamped `CollectionTime`/`SolutionVersion`/`TraceName` — and the actual rows hashtables nested inside `SyncRoot`.
- 🔧 **Root cause — exact mechanism, finally pinned down with an in-isolation PS 5.1 repro:**
  1. `Invoke-LogAnalyticsKqlQuery` returns `,@($resp.Results)` — comma-protected so PowerShell emits the rows array as a SINGLE value to the pipeline (preserves array shape across function-output unwrap). Correct.
  2. **Caller in pure-LA branch did `$rows = @(Invoke-LogAnalyticsKqlQuery ...)`** — the `@()` wrap re-wrapped that single comma-protected value into `[Object[1] of Object[N]]`. Verified: `@(f_with_comma).Count = 1` (not 2) when function returns 2 comma-protected rows. PS 5.1's `@()` semantics treat the comma-protected output as a single value to wrap, not as an array to preserve.
  3. The downstream `foreach ($r in $rows)` then iterated **once** with `$r = the inner row-array`, not the rows themselves.
  4. `foreach ($p in $r.PSObject.Properties)` enumerated `System.Array`'s native properties (Count / Length / SyncRoot / etc.) — that's where `_SIDirectRows`'s "rows" came from.
  5. Calculate-RiskScore + Select-Object then surfaced those Array properties as Excel columns; the real row data was buried in `SyncRoot`.
- 🔧 **Fix.** Drop the `@()` wrap at the caller. Plain assignment `$rows = Invoke-LogAnalyticsKqlQuery ...` correctly captures the inner rows array (PS 5.1 verified: count=2 for 2 rows, count=1 for 1 row, type=PSCustomObject for each element). Empty-result fallback `if ($null -eq $rows) { $rows = @() }` for the 0-row case.
- 🧰 **Verified end-to-end** with a PS 5.1 isolation test that reproduces the BROKEN current behavior (`rows.Count = 1, rows[0].GetType = System.Object[], cleanRows[0].Category = ''`) and the FIXED behavior (`rows.Count = 2, rows[0].GetType = PSCustomObject, cleanRows[0].Category = 'Lifecycle', ResultAll.Count = 2`). Test deleted after passing.
- 🧰 **`Invoke-LogAnalyticsKqlQuery` left UNCHANGED** (still returns `,@($resp.Results)`). The comma-protect is correct; only the caller's `@()` wrap was wrong.

### v2.1.203 — Initialize-LauncherConfig: snapshot params at function entry (fixes `_CfgWriteSnapshotAndPrune` Cannot-convert-to-String when a customer config bare-assigns `$Solution` / `$RepoRoot`)

- 🔧 **Bug — engine launch failed at the layered-config stage** with `_CfgWriteSnapshotAndPrune : Cannot convert value to type System.String. (...) InvalidCastFromAnyTypeToString` at `Initialize-LauncherConfig.ps1` line 532. Customer's debug confirmed: by the time line 532 ran, `$Solution` and `$RepoRoot` were empty (`$Engine` happened to survive). Engine never got a chance to start.
- 🔧 **Root cause.** `Initialize-LauncherConfig` dot-sources up to 5 layered config files (`. $sharedPath`, `. $platformPath`, `. $solutionCustom`, `. $defaultsPath`, `. $customPath`) into its OWN function scope. Any bare assignment in a customer-owned layer file — `$Solution = ...`, `$RepoRoot = ...`, `$Engine = ...`, etc. **without the `$global:` prefix** — silently overwrites the function's local parameters. Once cleared, the next call that takes those as `[Parameter(Mandatory)][string]` args fails parameter binding with the cast error.
- 🔧 **Fix.** Snapshot all five params (`$RepoRoot`, `$Solution`, `$Engine`, `$LauncherDir`, `$Mode`) into uniquely-named locals (`$__siRepoRoot`, etc.) **before** any dot-sourcing happens. Use those snapshots for the `_CfgWriteSnapshotAndPrune` call at line 532. Robust against a customer bare-assignment in any layer file — the function's internal state is now insulated from layer-file scope leak.

### v2.1.202 — RiskAnalysis: pure-LA route ships rows in `_SIDirectRows` marker (fixes Excel rows showing System.Array members `Length`/`Rank`/`SyncRoot` instead of real columns)

- 🔧 **Bug — pure-LA reports wrote rows to Excel with only `SecurityDomain` populated, every other column blank, and weird columns `Length` / `Rank` / `IsFixedSize` / `Count` / `SyncRoot` appearing on each row.** Customer dump showed each export-pool entry was actually a `System.Object[]` packing all the report's rows in `SyncRoot`; `Select-Object -Property` then surfaced `System.Array`'s .NET properties instead of the rows' real columns. Reports with 1 result row → Count=1; 2 result rows → Count=2; 0 result rows → Count=0 — exact match for "rows packed inside the array".
- 🔧 **Root cause** (two layers):
  1. v2.1.199's pure-LA route mocked the Microsoft Graph response shape `[pscustomobject]@{ Results = @( [pscustomobject]@{ AdditionalProperties = $hash } ) }` and relied on the engine's `$resp.Results.AdditionalProperties` PowerShell property broadcast. That broadcast works cleanly for the Graph SDK's strongly-typed `Generic<T>` collections; for a 1-element `Object[]` of PSCustomObjects PowerShell's behavior was inconsistent enough that downstream `Calculate-RiskScore` ended up iterating the WHOLE row-array as a single "row".
  2. The intermediate v2.1.202 first-pass fix introduced a marker property `_SIDirectRows = ,@($cleanRows.ToArray())` — but the **comma-protect** wrapped the array in another 1-element outer array. Engine read back `[array-of-1-array]`, `foreach` iterated once with `$row = the inner array`, the export pool got a `System.Array` as a single row, downstream `Select-Object` surfaced `System.Array` .NET properties.
- 🔧 **Final fix.** Drop the comma-protect: `_SIDirectRows = $cleanRows.ToArray()` (plain assignment). Engine reads back the array directly, iterates each row as a clean PSCustomObject. **Verified end-to-end** with a 2-row repro: BROKEN path gives `pool[0].GetType() = System.Object[]` (the bug); FIXED path gives `pool.Count = 2` with both rows accessible as `PSCustomObject` and all column values intact.
- 🔧 **Engine bypass** (carried over from v2.1.202 first pass): both call-sites (single-shot + bucketing) check for the `_SIDirectRows` marker and use the rows directly when present, skipping the `.AdditionalProperties` + `ConvertTo-PSObjectDeep` dance that only makes sense for Microsoft Graph SDK responses. Falls through to the existing unwrap when absent (normal Graph hunting). Zero impact on non-LA-routed queries.
- 🧰 **Safety-net blacklist** for column-list build: `$systemArrayProps = @('Count','IsFixedSize','IsReadOnly','IsSynchronized','Length','LongLength','Rank','SyncRoot')` is now excluded when discovering "extra" columns from `$RiskScoreArray`'s first row. Belt-and-suspenders against any future regression where a wrapped-array row ever reaches this stage — those `System.Array` .NET property names can never end up in the Excel column list again.

### v2.1.201 — 4 new locked reports (PowerUser + RegularUser NoMFA, Tier 2 / Tier 3) + targeted 413 + sign-in-table error message

- 🆕 **`Identity_PowerUser_NoMFA_Summary` + `Identity_PowerUser_NoMFA_Detailed`** — Tier 2 users with no MFA registration. Tier 2 covers business owners / app owners / finance / HR / developers with elevated app access. RiskFactor_Consequence = 2; severity Medium-High. Probability factors: stale login (>90d), on-prem-synced, account >1y old. ConfigurationId `IDENTITY-MFA-003`.
- 🆕 **`Identity_RegularUser_NoMFA_Summary` + `Identity_RegularUser_NoMFA_Detailed`** — Tier 3 users with no MFA registration. Volume here typically dwarfs higher tiers; even one regular user without MFA is the most common phishing/password-spray initial-access vector. RiskFactor_Consequence = 1; severity Medium. Same probability factors as PowerUser variant. ConfigurationId `IDENTITY-MFA-004`.
- 🧰 **All four use the `EffectiveTier == N` filter pattern** consistent with the existing `Identity_PrivilegedUser_NoMFA_*` (Tier 0/1) reports. Excludes guest / B2B (handled by separate stale-guest report) and accounts younger than 7 days (provisioning grace period).
- 🧰 **Pure-LA queries** (only touch `SI_IdentityAssets_CL`, no XDR tables) — under v2.1.200 routing they submit directly to LA, no advanced hunting round trip, no body-size limit. Should run cleanly on bare LA workspaces without Sentinel data lake.
- 🧰 **Both orchestrators registered** — Summary entries in `RiskAnalysis_Summary_Bucket`, Detailed entries in `RiskAnalysis_Detailed_Bucket`. Total locked-report count: **100 → 104**. README § 6.9 inventory table renumbered (rows 67–100 → 71–104), teaser WOW table count updated, § 6.9 header count updated.
- 🔧 **Targeted 413 error message.** Previously the 413 handler emitted both fixes (forward sign-in logs to LA + enable Sentinel data lake mirroring) for every 413, even when the failing query had nothing to do with sign-in tables. Now the engine inspects the failing query (with KQL string literals stripped, same v2.1.200 trick to avoid `"Identity"` false positives) and:
  - **If the query references `AADSignInEvents` / `EntraIdSignInEvents` / `GraphAPIAuditEvents`** → emit BOTH fixes, with the sign-in-log forwarding labelled "PREFERRED FOR SIGN-IN REPORTS".
  - **Otherwise** → emit only the data-lake-mirroring fix (and a fallback hint to drop wide columns from `IdentityAssetsCollect` ingestion).
- 🔧 **Sign-in table classifier in `Get-DefenderTableOwner`** — the AAD/EntraId sign-in / GraphAPIAuditEvents branch now mentions the LA-forwarding alternative inline so customers see it both in the schema-error path AND the 413 path.

### v2.1.200 — RiskAnalysis: strip KQL string literals before XDR detection (fixes v2.1.199 false-positive on `"Identity"` / `"Email"` column values) + size-warning format-string fix

- 🆕 **`Identity_PowerUser_NoMFA_Summary` + `Identity_PowerUser_NoMFA_Detailed`** — Tier 2 users with no MFA registration. Tier 2 covers business owners / app owners / finance / HR / developers with elevated app access. RiskFactor_Consequence = 2; severity Medium-High. Probability factors: stale login (>90d), on-prem-synced, account >1y old. ConfigurationId `IDENTITY-MFA-003`.
- 🆕 **`Identity_RegularUser_NoMFA_Summary` + `Identity_RegularUser_NoMFA_Detailed`** — Tier 3 users with no MFA registration. Volume here typically dwarfs higher tiers; even one regular user without MFA is the most common phishing/password-spray initial-access vector. RiskFactor_Consequence = 1; severity Medium. Same probability factors as PowerUser variant. ConfigurationId `IDENTITY-MFA-004`.
- 🧰 **All four use the `EffectiveTier == N` filter pattern** consistent with the existing `Identity_PrivilegedUser_NoMFA_*` (Tier 0/1) reports. Excludes guest / B2B (handled by separate stale-guest report) and accounts younger than 7 days (provisioning grace period).
- 🧰 **Pure-LA queries** (only touch `SI_IdentityAssets_CL`, no XDR tables) — under v2.1.200 routing they submit directly to LA, no advanced hunting round trip, no body-size limit. Should run cleanly on bare LA workspaces without Sentinel data lake.
- 🧰 **Both orchestrators registered** — Summary entries in `RiskAnalysis_Summary_Bucket`, Detailed entries in `RiskAnalysis_Detailed_Bucket`. Total locked-report count: **100 → 104**. README § 6.9 inventory table renumbered (rows 67–100 → 71–104), teaser WOW table count updated, § 6.9 header count updated.

### v2.1.200 — RiskAnalysis: strip KQL string literals before XDR detection (fixes v2.1.199 false-positive on `"Identity"` / `"Email"` column values) + size-warning format-string fix

- 🔧 **Bug — v2.1.199 routing fix didn't fire on the very queries it was meant to fix.** Customer's `Identity_AdminAccount_HasMailbox_Summary` (and `_NeverUsed_Summary`, `_OnPremSynced_Summary`) reports — pure-LA, only touch `SI_IdentityAssets_CL` — still bridged through advanced hunting and hit `413`. Root cause: my XDR-detection regex `\bIdentity(?!Assets)\w*\b` matched the **column-value string literal** `"Identity"` in `| extend SecurityDomain = "Identity"`. Same trap for any pure-LA query containing `"Email"`, `"DeviceInfo"`, etc. as a literal value. Engine misclassified those as "mixed XDR" and forced them through the let-block bridge → nginx 413 on big estates.
- 🔧 **Fix — strip KQL string literals + line comments before running the XDR regex.** v2.1.200 pre-processes the query body (removes `"..."`, `'...'`, `@'...'`, `@"..."`, and `// ...` runs) before pattern matching, so only actual table references can trip the regex. **Verified with 7-case smoke test** covering: literal `"Identity"` / `"Email"` / `"DeviceInfo"` strings (all correctly classified pure-LA), `extract(@'...regex pattern...', ...)` arguments, and 3 mixed-query shapes (DeviceInfo / IdentityInfo / ExposureGraphNodes joins — all correctly classified mixed). Test deleted after passing; the regex itself ships as the production check.
- 🔧 **Bug — `{0} KB` printed literally** in v2.1.197's let-block size warning. Cause: PowerShell's `-f` operator binds tighter than `+`, so `("...{0}..." + "..." + "..." -f $sizeKb)` formats only the LAST string (which has no placeholders) and concatenates it with the first two unformatted strings. Fix: parenthesise the whole concat — `(("..." + "..." + "...") -f $sizeKb)`.
- 🧰 **Customer impact.** After this fix the failing reports route directly to LA (no let-block, no 413). LA's body cap and result cap (~64 MB / 500k rows / 10 min) is orders of magnitude beyond anything RiskAnalysis needs. Mixed XDR queries (those that genuinely join `SI_IdentityAssets_CL` against `Device*` / `Identity*` / `ExposureGraph*` etc.) still go through the let-block bridge and remain subject to advanced hunting's body cap — for those, Sentinel data lake mirroring of `SI_IdentityAssets_CL` is the only proper fix (engine then bypasses the bridge entirely).

### v2.1.199 — RiskAnalysis: route pure-LA queries directly to Log Analytics (avoids 413) · `WriteJsonOutput` default OFF · `AutoBucketMax` default raised to 1024

- 🔧 **Bug — `413 Request Entity Too Large` from nginx in front of advanced hunting.** v2.1.197's `SI_IdentityAssets_CL` bridge prepended a `let SI_IdentityAssets_CL = datatable(...) [...];` block in front of every query that referenced the table. For tenants with non-trivial estates (a few thousand users × wide columns like `CSA` JSON / `TierSources` / `Workload_Credentials` at 1–5 KB per row), the let-block exceeded **the nginx body cap that sits in front of `graph.microsoft.com/security/runHuntingQuery`** (the request never reaches the hunting backend — nginx returns raw HTML 413). My v2.1.197 size warning fired at 700 KB based on a guess; reality is the cap is hit somewhere lower for some customer payloads.
- 🔧 **Fix — split routing by query shape.** The bridge now inspects the customer's KQL *before* deciding how to submit:
  - **Pure-LA queries** (touch only `*_CL` tables — the case for the majority of identity-only reports): submit the **whole** query directly to `Invoke-AzOperationalInsightsQuery`. **No let-block. No advanced-hunting round trip. No nginx 413 risk.** Body becomes just the customer's report KQL (a few KB). Result-set cap is LA's native ~64 MB / 500k rows.
  - **Mixed queries** (joining `SI_IdentityAssets_CL` with `Device*` / `Identity*` / `ExposureGraph*` etc.): same let-block bridge as v2.1.197 — only viable path. Still subject to the nginx body cap. Recommendation in the warning: enable Sentinel data lake + table mirroring to make `SI_IdentityAssets_CL` natively visible in advanced hunting (engine probe then bypasses the bridge entirely).
  - **Mocked Microsoft Graph response shape** for the LA-direct path so the engine's downstream consumers (`$resp.Results.AdditionalProperties` access pattern) don't need to change.
- 🧰 **XDR-table detection regex** classifies queries by referenced-table prefix: `Device(?!Tvm)\w*`, `DeviceTvm\w*`, `Identity(?!Assets)\w*`, `ExposureGraph\w*`, `Email\w*`, `Message\w*`, `UrlClickEvents`, `CloudApp\w*`, `AppFile\w*`, `Cloud(?:Audit|Dns|Process|Storage)\w*`, `Alert(?:Evidence|Info)`, `Behavior(?:Entities|Info)`, `AAD\w*SignIn\w*`, `EntraId\w*SignIn\w*`, `GraphAPIAuditEvents`. `\b` word-boundaries on both sides ensure `SI_IdentityAssets_CL` never trips the `Identity*` branch (no word boundary between `_` and `I`).
- 🔧 **Default change — `$global:WriteJsonOutput` flipped from `$true` to `$false`.** The XLSX already covers reporting + Power BI ingestion; the JSON sibling exists only for customers wiring an external machine-readable pipeline. Defaulting it ON wrote a duplicate file every run for no benefit. Enable in `LauncherConfig.custom.ps1` if you need it. `LauncherConfig.sample.ps1` updated to match the new default.
- 🔧 **Default change — `$global:AutoBucketMax` raised from `64` to `1024`.** AutoBucket only escalates when needed (small tenants still run at low counts); the previous cap of 64 was too low for large estates where some reports legitimately need 100s of buckets to stay under the 30k-row hunting ceiling. CLI `[ValidateRange]` widened from `(1,512)` to `(1,2048)` across all 4 launcher templates so the new default is acceptable from the command line, and the launcher templates' own `$AutoBucketMax_Default` fallback raised from 512 to 1024 to match.
- 🔧 **Layered-config bug fix in launcher templates.** All 4 RiskAnalysis launcher templates had the unsafe pattern `if ($cliBound.ContainsKey('AutoBucketMax')) { ... } else { $global:AutoBucketMax = $AutoBucketMax_Default }` — the bare `else` **stomped** any value set in Layer 4 (`LauncherConfig.defaults.ps1`) or Layer 5 (`LauncherConfig.custom.ps1`) when no CLI arg was passed. Converted to the safe layered pattern (CLI > existing layered global > template fallback default), matching the v2.1.187 / v2.1.189 sweep.

### v2.1.198 — IdentityAssetsCollect bulk MFA fix · RiskAnalysis no-retry on schema errors · README Defender XDR licensing section

- 🔧 **Bug — silent MFA mis-classification.** A real customer hit `MFAMethodCount = 0` / `MFARegistered = false` for a user (`kdahl@pingala.eu`) who had **2× Microsoft Authenticator + 2× Windows Hello for Business** registered in the Entra portal. Root cause: the MFA-method block at `IdentityAssetsCollectDefineTierIngestLog.ps1` line 2654 made one Graph call per user (`/users/{id}/authentication/methods`) wrapped in an empty `catch {}` — any throw (transient 404 / 403 / parse failure / Graph quirk) silently produced `MFA = false` with **no log line at all**. Per-user errors were invisible.
- 🔧 **Fix — bulk endpoint as primary, logged per-user fallback.** Engine now fetches `/reports/authenticationMethods/userRegistrationDetails?$top=999` **once at startup**, caches by `ObjectId`. The per-user MFA block now (a) looks up the cache first and uses `isMfaRegistered` / `methodsRegistered` / `isPasswordlessCapable` directly — same authoritative source the Entra portal "Authentication methods activity" page uses; (b) only falls back to the per-user `/authentication/methods` call when the bulk lookup misses (e.g. a brand-new user not yet in the report — typical ~24h propagation); (c) the fallback `catch` now writes `Write-Warn ("MFA fetch failed for {0} ({1}): {2}" -f $upn, $user.id, $exception)` so silent failures stop being silent.
- 🧰 **Performance side-effect.** One paged call now replaces N per-user calls. On a 5k-user tenant: ~5000 Graph round-trips → 5–6 paged round-trips. Materially faster + much less throttle exposure. Same `UserAuthenticationMethod.Read.All` permission already granted by Step1 — no new perms required.
- 🔧 **Bug — pointless retries on deterministic schema errors.** `Invoke-GraphHuntingQuery` retried 4 times (~12s of waiting) on `Failed to resolve table or column expression named 'X'` errors — but missing tables don't appear via retry; the failure is deterministic. Same customer hit this with `DeviceInfo` (advanced-hunting EDR table that requires MDE Plan 2 — they'd just migrated from Defender for Business and the table hadn't propagated yet).
- 🔧 **Fix — schema-error short-circuit + ownership classification.** Engine now detects the resolve error pattern, captures the missing table name, classifies it via the new `Get-DefenderTableOwner` helper (`Device*` → MDE P2, `DeviceTvm*` → MDVM, `Identity*` → MDI, `ExposureGraph*` → MDEM, `Email*` → MDO, `CloudApp*` → MDA, `Cloud(Audit|Dns|Process|Storage)*` → Defender for Cloud, `*_CL` → custom LA, etc.), logs ONE clear `[WARN]` line that tells the customer exactly which Defender service / SKU is missing, and **throws without retrying**. Outer report loop continues to the next report. Saves ~12s per failed report and de-noises the log.
- 📚 **README — new § 3.5.4 "Defender XDR licensing & onboarding requirements"** with the full table-family → service map, the **MDE Plan 1 vs Plan 2 trap** (Devices Inventory page renders for both SKUs but only P2 exposes `Device*` to advanced hunting — the exact gotcha that surfaced today), the post-upgrade propagation window (~24h), the new schema-error log line shown verbatim, and a recommendation to confirm table presence in the Defender XDR Hunting → Schema browser before onboarding a new tenant. TOC updated with the new § 3.5.4 entry.

### v2.1.197 — RiskAnalysis: transparent `SI_IdentityAssets_CL` bridge for workspaces without Sentinel data lake mirroring

- 🔧 **Bug.** Standing up RiskAnalysis on a fresh Log Analytics workspace **without Sentinel + data lake** failed every report whose KQL touched `SI_IdentityAssets_CL`: advanced hunting (Microsoft Graph `/security/runHuntingQuery`) only sees XDR tables and `IdentityInfo`/`ExposureGraph*` etc. Custom `*_CL` tables in LA are invisible to that endpoint unless data lake table mirroring is enabled. 148 query references in `SecurityInsight_RiskAnalysis_Queries_Locked.yaml` died with `'where' operator: Failed to resolve table or column expression named 'SI_IdentityAssets_CL'`.
- 🔧 **Fix.** New transparent bridge in the engine (`SecurityInsight_RiskAnalysis.ps1`, helpers inserted between `Ensure-GraphAuth` and `Invoke-GraphHuntingQuery`):
  1. **Lazy probe.** First time a query references `SI_IdentityAssets_CL`, the engine submits `SI_IdentityAssets_CL | take 1` directly to advanced hunting and caches the result for the rest of the run. If it succeeds (data lake mirroring active) → submit every subsequent query as-is; **zero overhead, zero behavior change**.
  2. **Inline-datatable fallback.** If the probe returns the resolve error, the engine fetches `SI_IdentityAssets_CL | summarize arg_max(CollectionTime, *) by ObjectId` from `$global:WorkspaceResourceId` **once per run** via `Invoke-AzOperationalInsightsQuery` (reuses the existing `Connect-AzAccount` SPN session — no token plumbing, no REST), caches the rows, and prepends a `let SI_IdentityAssets_CL = datatable(col1:type, col2:type, ...) [row1; row2; ...];` block to every query that references the table. Customer KQL is **unmodified** — the `let` definition shadows the missing table reference.
- 🧰 **17000 lines of YAML queries unchanged.** The 148 references to `SI_IdentityAssets_CL` keep working as-is; bridge logic is invisible to query authors.
- 🧰 **Cleaner choice over hand-rolled REST.** First draft used `Invoke-RestMethod` against `api.loganalytics.io` with manual `Get-AzAccessToken` + customer-id resolution; switched to `Invoke-AzOperationalInsightsQuery` from `Az.OperationalInsights` (already in `$script:SecurityInsight_RequiredModules` via the `Az` meta-module). One cmdlet call, no token retrieval.
- 🧰 **Caveat documented in code.** KQL request body is bounded (~1 MB). Estates with >~5k assets carrying large columns (`CSA`, `Workload_Credentials`) may exceed the cap; engine logs a clear warning over 700 KB and recommends Sentinel data lake + table mirroring for that case.
- 🧰 **Helpers added (all internal):** `Resolve-WorkspaceCustomerId` (cached ResourceId → GUID), `Invoke-LogAnalyticsKqlQuery` (thin wrapper around `Invoke-AzOperationalInsightsQuery`), `Get-IdentityAssetsSnapshot` (lazy + cached LA fetch), `ConvertTo-KqlStringLiteral` + `ConvertTo-KqlDatatableLet` (KQL literal builder with proper backslash / quote / control-char escaping), `Get-IdentityAssetsLetBlock` (cached let-block builder + size-warning), `Test-AdvancedHuntingHasIdentityAssets` (lazy + cached probe). Probe call uses `Start-MgSecurityHuntingQuery` directly to avoid recursion through the bridge.

### v2.1.196 — IdentityAssetsCollect defaults: drop `WorkspaceResourceId` + `ExportDestination` pre-declarations

- 🧰 **Removed two `if (-not (Test-Path ...)) { $global:Foo = $null }` lines** for `$global:WorkspaceResourceId` and `$global:ExportDestination` from `LAUNCHERS/IdentityAssetsCollectDefineTierIngestLog/LauncherConfig.defaults.ps1`. Both are off-by-default tenant-specific values that the customer sets in `CUSTOMDATA\SecurityInsight.custom.ps1` (Layer 3) or this engine's `LauncherConfig.custom.ps1` (Layer 5). The defaults file shouldn't even mention them — every line in the snapshot's "Layer 4 - LauncherConfig.defaults" group should be a value SI ships, not a tenant artifact.
- 🧰 **Why this is safe.** The `IdentityAssetsCollectDefineTierIngestLog` engine runs `Set-StrictMode -Off` (line 726) and reads both variables via `[string]::IsNullOrWhiteSpace($global:Foo)` checks — an unset variable is treated as "feature off" without throwing. The pre-declarations were defensive-but-unnecessary holdovers from the v2.1.189 sweep that converted unconditional assignments to conditional.
- 📚 **Comment block at the top of the DCR INGESTION section** explains the intentional omission so future maintainers don't add them back.

### v2.1.195 — Step3 end-of-run + sample now include `$global:BuildSummaryByAI = $true` (the master toggle)

- 🔧 **Bug.** Step3's "Copy into LauncherConfig.custom.ps1 (SecurityInsight_RiskAnalysis):" print-out emitted the 5 `$global:OpenAI_*` lines but **not** `$global:BuildSummaryByAI = $true`. Customers who pasted the block verbatim into RiskAnalysis got the OpenAI endpoint configured correctly, but `BuildSummaryByAI` defaulted to `$false` so the AI summary was silently skipped on every run.
- 🔧 **Fix.** Step3 print-out now leads with the master toggle line **in green** so it's visually obvious it must be present:
  ```
    $Global:BuildSummaryByAI           = $true                       <- master toggle
    $Global:OpenAI_apiKey              = "..."
    $Global:OpenAI_endpoint            = "..."
    $Global:OpenAI_deployment          = "..."
    $Global:OpenAI_apiVersion          = "..."
    $Global:OpenAI_MaxTokensPerRequest = 16384
  ```
  Header callout above the block makes the dependency explicit: *"the BuildSummaryByAI master toggle is REQUIRED — without it, the engine ignores the OpenAI_* values and skips the AI summary entirely"*.
- 📚 **`Step3 LauncherConfig.sample.ps1` updated** with a 12-line IMPORTANT block at the bottom of the minimum-copy-paste section explaining: Step3 only PROVISIONS resources; to USE them in RiskAnalysis you also need to add 6 globals (the toggle + the 5 OpenAI_* lines) to RiskAnalysis's own `LauncherConfig.custom.ps1`. Step3's end-of-run output prints the lines with real values pre-filled.
- 🧰 **Setup Configurator unaffected** — it generates Step3's OWN config (which doesn't include `BuildSummaryByAI` because that's a RiskAnalysis variable, not a Step3 variable). Cross-tab dependency is documented in the sample file.

### v2.1.194 — Step3 OpenAI: ship the missing `LauncherConfig.defaults.ps1`

- 🔧 **Bug.** `Step3_OnboardValidate-SecurityInsight-OpenAI-PAYG-Instance-Azure` was the only Step engine without a Layer-4 `LauncherConfig.defaults.ps1`. Customers who ran it without setting every optional global hit `The variable '$global:ModelVersion' cannot be retrieved because it has not been set.` — `Set-StrictMode` in the engine fires `VariableIsUndefined` the moment it touches an unset name, even inside an `if ($global:ModelVersion)` existence check.
- 🔧 **Fix.** New `LAUNCHERS/Step3_*/LauncherConfig.defaults.ps1` declares all 12 customer-tunable globals up front using the conditional pattern `if (-not (Test-Path variable:global:X)) { $global:X = <default> }`. Every engine read now resolves to a real (possibly `$null`) variable. Customer values from Layer 3 / 5 still win — verified via smoke test (set `$global:ModelVersion = '2024-08-06'` + `$global:Capacity = 50` before dot-sourcing → both survive).
- 🧰 **Globals declared:** `SubscriptionId` / `ResourceGroupName` / `Location` / `AccountName` / `DeploymentName` (no safe default — pre-declared `$null`, engine has its own fail-fast); `ModelName` (`gpt-4.1-mini`); `ModelVersion` (`latest`); `Capacity` (100); `PublicNetworkAccess` (`Enabled`); `WaitForAccountReady` (`$true`); `DeploymentSkuOrder` (`@('GlobalStandard')`); `WriteModelDumps` (`$true`).

### v2.1.193 — Replace stale user-facing `LauncherConfig.ps1` references with `LauncherConfig.custom.ps1` (37 hits across 19 files)

- 📚 **Step2's `[ADMIN] Paste the block below into LauncherConfig.ps1 ...` print-out now says `LauncherConfig.custom.ps1`** — same for the path on the next line (`LAUNCHERS\IdentityAssetsCollectDefineTierIngestLog\LauncherConfig.custom.ps1`). Customers following Step2's end-of-run instructions were being told the wrong filename.
- 📚 **Sample-config docstrings, "no auth method configured" throw text, "reads credentials from" engine docstrings, and Step0 update-policy comments** all updated to point at `LauncherConfig.custom.ps1`. 37 replacements across 19 files (launcher templates, sample.ps1 / defaults.ps1 docstrings, engine .ps1 doc comments, Step0 / Step2 / IdentityAssetsCollect engine messages).
- 🧰 **Intentionally left alone** (these are NOT bugs):
  - `Initialize-LauncherConfig.ps1`'s legacy-fallback code + documentation (the loader still accepts a literal `LauncherConfig.ps1` filename for backward compat with pre-v2.1.147 installs).
  - Step0's `PreservePatterns` list still includes both `'launchers\*\LauncherConfig.ps1'` AND `'launchers\*\LauncherConfig.custom.ps1'` so legacy installs aren't broken on update.
  - Every reference to `Initialize-LauncherConfig.ps1` (that is the loader's actual filename, not the customer config file).

### v2.1.192 — Step1 + Step4 launchers: auth fields fall back to runtime `$global:Spn*` globals when Step-specific names aren't set

- 🔧 **Bug.** Customer who set `$global:OnboardValidate_AuthMethod = 'SpnSecret'` in their Step1 `LauncherConfig.custom.ps1` plus the runtime SPN values `$global:SpnTenantId / SpnClientId / SpnClientSecret` (already populated for every other engine) hit `ConvertTo-SecureString : Cannot bind argument to parameter 'String' because it is an empty string` — Step1 was reading only `$global:OnboardValidate_AuthTenantId / _AuthClientId / _AuthClientSecret`, ignoring the runtime SPN globals. Same naming-prefix isolation existed in Step4 (`$global:Step4_Auth*`).
- 🔧 **Fix (Step1 + Step4 launcher templates × 4 flavours each = 8 files).** The auth-value splat now uses an inline `if (...) { Step-specific } else { runtime SPN }` per field:
  ```powershell
  AuthTenantId = if ($global:OnboardValidate_AuthTenantId) { $global:OnboardValidate_AuthTenantId } else { $global:SpnTenantId }
  AuthClientId = if ($global:OnboardValidate_AuthClientId) { $global:OnboardValidate_AuthClientId } else { $global:SpnClientId }
  ...
  ```
  Same pattern in Step4 with `$global:Step4_*` overrides falling back to `$global:Spn*`. Backwards compatible: customers who set the Step-specific names (or use the Setup Configurator, which generates them) keep working; customers who only set the runtime `Spn*` names now also work.
- 🧰 **Audit confirmed Step2 + Step3 are clean** — both already read `$global:SpnTenantId / SpnClientId / SpnClientSecret` directly, no naming-prefix isolation. Same for the runtime ingestion / tagging engines.
- 🧰 **Setup Configurator unaffected.** The Step1 tab emits `OnboardValidate_*` names; the Step4 tab emits `Step4_*` names; both match the launcher splat keys. The fallback only kicks in for manually-crafted configs.

### v2.1.191 — Step1 Permissions: drop device-code fallback + add `-Force` to clear stale Az context on Interactive sign-in

- 🔧 **`Step1_OnboardValidate-SecurityInsight-Permissions.ps1` no longer falls back to `Connect-AzAccount -UseDeviceAuthentication`.** Removed the inner try/catch that retried with device code when the browser credential threw `MissingMethodException`. Any failure now surfaces directly to the outer catch with the real error message — useful when (for example) `Connect-AzAccount` works fine in a manual ISE session but the Step1 launcher fails for a different reason that the device-code retry was masking.
- 🔧 **Added `-Force` to `Connect-AzAccount` on the Interactive path.** Diagnoses + prevents the "stale Az session from a prior PowerShell window throws confusing errors" trap. Previously the user had to run `Disconnect-AzAccount` manually before re-running Step1; now `-Force` discards any cached token/context for the same user automatically and re-authenticates fresh. Recurrent / scheduled re-runs aren't affected because Step1 is a one-shot onboarding tool, not a hot-path engine.
- 🧰 **Side benefit.** The hint block that fired on `MissingMethodException` (Az.Accounts / Azure.Identity DLL mismatch — `Update-Module Az.Accounts -Force` + restart PowerShell) still triggers via the outer catch, so the diagnostic guidance for that specific case is unchanged.

### v2.1.190 — Refresh sample XLSX files in `DATA/_samples/`

- 📚 **Refreshed `Sample - RiskAnalysis_Summary_Bucket.xlsx` + `Sample - RiskAnalysis_Detailed_Bucket.xlsx`** from a recent live run. The README "Sample output" table links land on these files; previous copies pre-dated the v2.1.158-onward column / TraceName / TraceID changes and the v2.1.175 Azure RBAC catalog populating fix. Net delta is shape, not content semantics — same model, just a current-shape preview.

### v2.1.189 — Layer-4 defaults no longer stomp Layer 3 values in 4 more engines (IdentityAssets / Step1 / Step2 / Step4)

- 🧰 **Audit sweep** triggered by the v2.1.177 fix (which only covered Build_Tier + RiskAnalysis). Found 49 more unconditional `$global:X = <default>` assignments in the following `LauncherConfig.defaults.ps1` files, every one of them stomping a customer value that may have been set in `SecurityInsight.custom.ps1` (Layer 3):
  - **`LAUNCHERS/IdentityAssetsCollectDefineTierIngestLog/LauncherConfig.defaults.ps1`** — 15 patches (`WorkspaceResourceId`, `DceIngestionUri`, `DcrName`, `TableName`, `Defender_WorkspaceNameResourceId`, `WriteJsonOutput`, `ExportDestination`, `CsaAttributeSet`, `BatchSize`, `SubscriptionNameExcludePatterns`, `TenantDomain`, `TroubleshootingMode`, `WhatIfMode`, `SuppressErrors`, `SuppressWarnings`)
  - **`LAUNCHERS/Step1_OnboardValidate-SecurityInsight-Permissions/LauncherConfig.defaults.ps1`** — 12 patches (`OnboardValidate_SpnDisplayName`, `OnboardValidate_SpnAppId`, `OnboardValidate_AzureRbacScope`, `OnboardValidate_AzureSubscriptionIds`, `OnboardValidate_DefenderWorkspaceResourceId`, `OnboardValidate_DcrResourceId`, `OnboardValidate_AuthMethod`, `OnboardValidate_AuthTenantId`, `_AuthClientId`, `_AuthClientSecret`, `_AuthCertificateThumbprint`, `OnboardValidate_WhatIfMode`)
  - **`LAUNCHERS/Step2_OnboardValidate-SecurityInsight-LogAnalytics/LauncherConfig.defaults.ps1`** — 6 patches (`DcrName`, `TableName`, `WorkspaceRetentionDays`, `WhatIfMode`, `SuppressErrors`, `SuppressWarnings`)
  - **`LAUNCHERS/Step4_Deploy-SecurityInsight-PowerBI-Dashboard/LauncherConfig.defaults.ps1`** — 16 patches (Power BI workspace / report name, `.pbix` path, LA workspace ID, tenant ID, staleness-day thresholds, top-N, access group object ID, access group role, initial refresh toggle, Step4 auth method + credentials, WhatIfMode)
- 🔧 **All 49 assignments converted** to the `if (-not (Test-Path variable:global:X)) { $global:X = <default> }` pattern consistent with v2.1.177's fix.
- 🧰 **Completed the audit sweep triggered by v2.1.177** — Pattern A (launcher-template stomps) and Pattern C (launcher-local vars not re-read from globals) both came back clean across the remaining 10 engines; this was the last outstanding tranche of the bug class.

### v2.1.188 — RiskAnalysis launchers now honor customer `$global:RiskAnalysis_Summary_Override` / `_Detailed_Override` (Summary ↔ Detailed flip)

- 🔧 **Bug.** A customer who set `$global:RiskAnalysis_Detailed_Override = $true` (+ optionally `_Summary_Override = $false`) in Layer 3 / Layer 5 to flip the default Summary mode to Detailed was silently ignored. The launcher ran Summary mode anyway and wrote `RiskAnalysis_Summary_Bucket.xlsx` instead of the Detailed report.
- 🔧 **Root cause.** Each RiskAnalysis launcher template hardcodes **local** PowerShell variables `$Summary_Override = $true` and `$Detailed_Override = $null` at the top of the file. `Resolve-RunMode` reads those local vars — not the `$global:RiskAnalysis_*_Override` globals the engine itself honors at lines 96–97. So customer intent loaded by `Initialize-LauncherConfig` never made it into the launcher's mode decision. By the time the engine's global-override safety-net ran (`if ([bool]$global:RiskAnalysis_Detailed_Override) { $global:Detailed = $true }`), the launcher had already locked `$global:ReportTemplate` to `RiskAnalysis_Summary_Bucket`, so the wrong bundle still ran.
- 🔧 **Fix.** Inserted a re-eval block between `Initialize-LauncherConfig` and `Resolve-RunMode` in all 4 flavours. If either `$global:RiskAnalysis_Summary_Override` or `$global:RiskAnalysis_Detailed_Override` is non-null, **both** local `$Summary_Override` / `$Detailed_Override` variables are rewritten from the customer globals (`$null` where the customer didn't set anything). This both (a) honors customer intent, and (b) avoids ending up with two hardcoded `$true` values that trip Resolve-RunMode's `'both true'` throw.
- 📋 **Precedence now:** `-Summary` / `-Detailed` CLI arg > customer `$global:RiskAnalysis_*_Override` (Layer 3 / Layer 5) > launcher-template local override default > `$RunMode_Default` > `AutomationFramework ? Summary : neither`.

### v2.1.187 — RiskAnalysis launcher templates no longer stomp Layer 3 customer values for feature toggles

- 🔧 **Same bug class as v2.1.177, found in the launcher templates themselves.** After `Initialize-LauncherConfig` loads Layers 1–5 (including customer's Layer 3 `SecurityInsight.custom.ps1`), the 4 RiskAnalysis launcher templates were running a block like:
  ```powershell
  $global:BuildSummaryByAI = $BuildSummaryByAI_Default
  if ($cliBound.ContainsKey('BuildSummaryByAI')) { $global:BuildSummaryByAI = [bool]$cliBound['BuildSummaryByAI'] }
  ```
  which unconditionally overwrote `$global:BuildSummaryByAI = $BuildSummaryByAI_Default` — stomping whatever Layer 3 set. On `community-vm` / `community-azure` the default is `$false`, so a customer who wrote `$global:BuildSummaryByAI = $true` in `SecurityInsight.custom.ps1` saw it silently reset to `$false` before the engine got to read it. The AI summary was therefore never built.
- 🔧 **Fix** (applied to all 4 flavours: community-vm / community-azure / internal-vm / internal-azure). Each feature-toggle global now uses a conditional-assignment pattern that honors any higher-priority layer's value and still lets a CLI arg win last:
  ```powershell
  if (-not (Test-Path variable:global:BuildSummaryByAI)) { $global:BuildSummaryByAI = $BuildSummaryByAI_Default }
  if ($cliBound.ContainsKey('BuildSummaryByAI')) { $global:BuildSummaryByAI = [bool]$cliBound['BuildSummaryByAI'] }
  ```
- 🔧 **Scope — 6 feature-toggle globals per template × 4 templates = 24 patches.** Affected names: `OverwriteXlsx`, `BuildSummaryByAI`, `AutoBucketCount`, `AutoBucketCache`, `ShowConfig`, `DebugQueryHash`. Left unchanged (these are launcher-flavour-owned and shouldn't be customer-set in Layer 3): `AutomationFramework`, `Summary` / `Detailed` (derived by `Resolve-RunMode`), `ReportTemplate` (already uses CLI > Override > Default chain), `AutoBucketMax` (already uses CLI-or-default), `ResetCache` (already has Override slot).
- 📚 **Precedence chain going forward:** CLI arg > Layer 5 per-engine custom > Layer 3 solution custom > launcher Default. The same bug class could lurk in other engines' launcher templates — if you hit it, the repro is a layer-snapshot log showing the customer value at L3 and the stomped default at the assignment line.

### v2.1.186 — TOC: list § 1 Introduction subsections (Outputs / Use-cases / 🤖 Agents / Sample output)

- 📚 **TOC now lists the four § 1 H3 subsections** under "1. Introduction" — `Outputs`, `Use-cases`, `🤖 SecurityInsight Agents (work in progress)`, `Sample output`. Previously these were rendered in the body but had no TOC entry, so readers couldn't jump straight to (e.g.) the new Agents roadmap from the top.
- 🧰 **Explicit `<a id>` anchors added** to each of the four headings (`outputs`, `use-cases`, `securityinsight-agents`, `sample-output`) so the TOC links resolve to predictable slugs rather than GitHub's auto-generated ones (which mangle the emoji + parens in the Agents heading to `#-securityinsight-agents-work-in-progress`).

### v2.1.185 — README: roadmap section "🤖 SecurityInsight Agents (work in progress)" after Use-cases

- 🆕 **New "🤖 SecurityInsight Agents (work in progress)" section** inserted between Use-cases and Sample output. 19 planned agents grouped into 6 themes:
  - **Context + enrichment** (Asset Owner Resolver, Remediation Playbook Linker, Blast-Radius Narrator, Exploit Intel Enricher)
  - **Ticketing + change management** (Ticket Bridge, Change-Window Scheduler, Approval Routing)
  - **Remediation authoring** (Fix-Script Drafter, Rollback Plan Generator)
  - **Tracking + escalation** (Progress Tracker, Burn-Down Dashboard, SLA Breach Detector, False-Positive Feedback Loop, Attestation)
  - **Reporting + communications** (Per-Team Digest, Executive Briefing)
  - **Compliance + correlation** (NIS2 / CIS Mapper, Incident-to-Finding Correlator, Community Query Harvester)
- 📚 **Explicit "work in progress" disclaimer** at the bottom of the section pointing readers at GitHub Issues to influence priority order — nothing in the list ships yet.

### v2.1.184 — Teaser hook rephrased; verified detection counts are already accurate (no change to numbers)

- 📚 **Teaser hook reworded.** *"Your Defender dashboard and an attacker's target list look very different."* → *"What you see on your Defender dashboard isn't what attackers see on their target list."* Same idea, more direct.
- 🧰 **Verified the count claims by deduplicating across every shipped query source** — `DATA/SecurityInsight_RiskAnalysis_Queries_Locked.yaml`, `CUSTOMDATA/SecurityInsight_RiskAnalysis_Queries_Custom.sample.yaml`, `DATA/_samples/SecurityInsight_RiskAnalysis_Queries_Custom.yaml` for RA; the matching three files for CAT. Result:
  - **RA reports — 100 unique** by `ReportName` (Locked=100, Samples=82 unique, **all 82 sample names already exist in Locked** → union=100).
  - **CAT rules — 180 unique** by full `AssetTagName` (Locked=180, Samples=177 unique, **all 177 sample names already exist in Locked** → union=180).
  - The teaser numbers were already correct. The v2.1.169 starter samples were promoted into Locked in v2.1.174, so the sample files now hold a strict subset.

### v2.1.183 — Teaser tighten: collapse three lines into the detection-table header, drop the graph-traversals paragraph

- 📚 **Removed** the `**Included in SecurityInsight today**` line and the `**📦 Detection queries + tagging rules**` subheader above Table 1.
- 📚 **Renamed the table header** from "Detection queries + tagging rules" / "Count" to **"📦 Detection queries + tagging rules — Included in SecurityInsight today"** / **"Count"**. One header now does the work of three lines.
- 📚 **Dropped the "These aren't signature-based detections..." paragraph** between Table 1 and Table 2 — the graph-traversals framing already appears in the § 1 Introduction, and the teaser reads tighter without it.

### v2.1.182 — Fix `###` rendering as literal text across § 4.x / § 5 / § 6.x (GFM `</details>` bug)

- 🔧 **Markdown rendering bug hitting 12 headings** — every `</details>` closer from the v2.1.163 collapse script was immediately followed by the next section's `### 4.4 ...` / `## 5. ...` / `### 6.2 ...` heading with no blank line. GitHub Flavored Markdown requires a blank line between a closing raw-HTML tag and the next markdown construct; without it, the `###` is rendered as literal text. Fixed headings: § 4.4, § 4.5, § 5 (YAML Concept H2), § 6.2, § 6.3, § 6.4, § 6.5, § 6.6, § 6.7, § 6.8, § 6.9, § 9 (What's New H2).
- 🔧 **Anchor placement corrected.** The back-compat `<a id="...">` tags for each of those sections were sitting INSIDE the previous `<details>` block (before the closer). They've been moved after `</details>` so they resolve against the new heading, not the tail of the previous section's collapsed body.
- 📚 **§ 3.11 renamed** `Step 5a — Endpoint asset tagging` → `Step 5a — Endpoint & Azure asset tagging` (heading + TOC) — the engine handles both in the same run; the old name was misleading.

### v2.1.181 — Simplify `Microsoft MVP (Security · Azure · Security Copilot)` → `Microsoft MVP` everywhere

- 📚 **Replaced 74 occurrences** across every README, script, launcher template, `LauncherConfig.defaults.ps1`, `LauncherConfig.sample.ps1`, and the Setup Configurator HTML. Both separator variants (`· ·` middle-dot and `, ,` comma) caught; zero remaining `Microsoft MVP (` matches.
- Rationale: shorter, reads cleaner in the script-banner footer line and the README author line; the MVP competency list was repeated everywhere without adding signal. The MVP competencies are on [mortenknudsen.net](https://mortenknudsen.net) for anyone who wants them.

### v2.1.180 — README teaser copy tweaks

- 📚 **"Out of the box — shipped as `Locked` content..."** heading renamed to **"Included in SecurityInsight today"**. Lighter, less jargon.
- 📚 **Table header "What"** changed to **"Detection queries + tagging rules"**. Self-describing, no duplicated subheader.
- 📚 **Dropped the "Same data your SOC already pays for..."** sentence from the paragraph under Table 1. The graph-vs-list framing is already made in the first sentence; the trailing clause was repeating itself.
- 📚 **"by the AI classifier; consumed by IdentityAssetsCollect..."** shortened to **"by the AI integration in SecurityInsight"**. The implementation detail about `IdentityAssetsCollect` belongs in § 3, not the teaser.
- 📚 **Removed the "Counts come from DATA/..." meta-note** under Table 2. Implementation plumbing details belong in § 6 / § 7, not in the marketing teaser.

### v2.1.179 — README: drop duplicate `# SecurityInsight` H1 + de-fade the teaser

- 📚 **Removed the `# 🛡️ SecurityInsight` H1** at the top of the README. GitHub renders the repo name as a heading at the very top of the rendered page automatically, so the markdown H1 was producing a duplicate "SecurityInsight" title. File now starts with the badges + author line.
- 📚 **Teaser no longer wrapped in a `>` blockquote.** GitHub renders `>` blockquotes in a lighter grey which looked faded against the surrounding full-contrast body text. The four teaser paragraphs are now plain paragraphs with the same bold / italic emphasis, so they read at full contrast. The strap line "🎯 Think like the hacker. Act like the defender. Fix what matters — first." promoted to an H3 so it stands on its own as a closing line.

### v2.1.178 — Teaser WOW table: Azure RBAC catalog now populates (+873 roles); grand total jumps to 2,297

- 📚 **Refreshed the AI-classified tier catalog numbers in the README teaser** from a live Build_Tier run on the v2.1.175/176/177 fixes. Key changes from the previously-published table:
  - 🆕 **Azure built-in roles row now populated** — 873 total (3 / 15 / 132 / 723 per Tier 0-3). Previously reported as "0 — classified at run-time" because the v2.1.174 engine was silently returning empty due to missing subscription context; v2.1.175 fixed that (`Set-AzContext` auto-selects the first subscription the SPN can read after `Connect-AzAccount`).
  - **Entra built-in roles** 142 → **143** (one new role appeared in the catalog).
  - **AD built-in groups** total unchanged at 69, but the AI re-tiered the distribution (9 / 8 / 1 / 51 instead of 10 / 5 / 3 / 51 — the classifier re-evaluates every run, and small tier shifts are normal).
  - **Entra / Graph API permissions** total unchanged at 1,212, distribution shifted (2 / 80 / 117 / 1,013 instead of 4 / 84 / 94 / 1,030).
  - **Grand total 1,423 → 2,297** (the Azure role catalog adding 873 entries accounts for virtually all of the jump).
- 📚 **Removed the "Azure RBAC classified at run-time" note below the table** — no longer accurate now that the catalog populates at Build_Tier time. Replaced with a note pointing at the JSON source file + the two `*_Catalog` fields (`Azure_Roles_Catalog` = 873 raw entries, `EntraID_APIPermissions_Catalog` = 1,845 raw entries) so downstream consumers know they're available too.

### v2.1.177 — Layer 4 defaults no longer clobber Layer 3 customer values (OpenAI / SMTP)

- 🔧 **Critical bug, masked by v2.1.176's fail-fast.** `Build_Tier_Definitions_JSON_File` and `SecurityInsight_RiskAnalysis` shipped `LauncherConfig.defaults.ps1` (Layer 4) files that **unconditionally** wrote `$global:OpenAI_ApiKey = $null`, `$global:OpenAI_Endpoint = $null`, `$global:OpenAI_Deployment = $null`, `$global:SMTPUser = $null`, etc. Since Layer 4 loads *after* Layer 3 (`SecurityInsight.custom.ps1`), those unconditional assignments stomped the customer's carefully-placed SPN / OpenAI / SMTP values. The v2.1.176 fail-fast validation then surfaced it as *"`$global:OpenAI_ApiKey is empty. Set it in SecurityInsight.custom.ps1 (Layer 3)…"*  — even though the customer **had** set it in Layer 3. The config-snapshot log in `DATA\LOGS\config-*.log` pinpoints the problem cleanly: under v2.1.176 it showed `OpenAI_ApiKey [L4 LauncherConfig.defaults]` with `len=0`, when the expected winning layer is Layer 3.
- 🔧 **Fix.** Both defaults files rewritten to **only set values when the variable is not already defined** (`if (-not (Test-Path variable:global:Foo)) { $global:Foo = <default> }`), and to **delete the 3 OpenAI + 4 SMTP unconditional null assignments** entirely — an unset global is already `$null` in PowerShell, so explicit `= $null` is never required and always dangerous in a Layer 4 file. Variables with a genuinely safe engine default (`AI_ChunkSize`, `AI_MaxTokens`, `AI_MaxRetries`, `OpenAI_apiVersion`, `SendMail=$false`, `SMTPPort=587`, etc.) keep their defaults but behind the conditional, so Layer 3 values still win.
- 📚 **Pattern going forward:** Layer 4 `LauncherConfig.defaults.ps1` must treat every `$global:` assignment as an opt-in fallback. If a customer could reasonably set the variable in Layer 3 / 5, the defaults file must use the conditional-assignment pattern. Unconditional writes in Layer 4 are a bug, not a safety net.

### v2.1.176 — Build_Tier AI retry: stop NRE'ing on unexpected Azure OpenAI response shapes

- 🔧 **Bug.** `Build_Tier_Definitions_JSON_File.ps1` was retrying every chunk with the cryptic warning `attempt N failed: Object reference not set to an instance of an object.` on *every* attempt, then falling back to the Tier-99 "unclassified" bucket after exhausting retries. The underlying issue wasn't an AI flake — it was an always-fails configuration problem that the response-parsing code was masking.
- 🔧 **Root cause.** After `Invoke-RestMethod` succeeded with a 200-OK body, the engine dereferenced `$response.choices[0].message.content.Trim()` with no null-check. When Azure OpenAI returns an **error envelope** instead of the expected completion — e.g. because the deployment name is wrong, the API key is revoked, a content-filter tripped, or the token budget was exceeded — the body shape is `{"error":{...}}` rather than `{"choices":[{...}]}`. Dereferencing the missing `.choices[0].message.content` on PS 5.1 throws `NullReferenceException`, surfaced as the familiar "Object reference not set to an instance of an object." line. Retrying doesn't help because the config / deployment issue is stable.
- 🔧 **Fix.**
  - **Fail-fast validation up front:** `$global:OpenAI_ApiKey` / `OpenAI_Endpoint` / `OpenAI_Deployment` are checked for non-empty *before* the first request. An empty value throws a clear error pointing at `SecurityInsight.custom.ps1` (Layer 3) / `LauncherConfig.custom.ps1` (Layer 5) + README § 3.8.
  - **Three explicit response-shape guards** after each `Invoke-RestMethod`: `$response` not null → `$response.choices` is a non-empty array → `$response.choices[0].message.content` not null. Each guard throws a descriptive error naming what's missing. For the "no choices" case it includes the raw error body (or the full response) as JSON so the user sees exactly what Azure OpenAI returned.
  - **WARN message now uses `$_.Exception.Message`** instead of the full `$_` — the message alone is what the user needs; the stack trace was adding noise.

### v2.1.175 — Build_Tier fixes: empty Azure role catalog + null EntraID_APIPermissions_Catalog

- 🔧 **Bug: `Azure_BuiltInRoles_Tier0..3` + `Azure_CustomRoles_Tier0..3` + `Azure_Roles_Catalog` came back empty in `DATA/SecurityInsight_IdentityTiering.json`.** Root cause: after `Connect-AzAccount -ServicePrincipal -TenantId <...>` the Az context had no default subscription selected, so `Get-AzRoleDefinition` (called with no `-Scope`) returned empty silently even when the SPN had `Reader` at tenant-root MG. The `Step1_OnboardValidate-SecurityInsight-Permissions` utility grants the right role; the engine just wasn't using it.
- 🔧 **Fix.** `Connect-AzWithSPN` in `Build_Tier_Definitions_JSON_File.ps1` now calls `Get-AzSubscription` after connecting, `Set-AzContext`s to the first subscription the SPN can see, and logs which one was picked. If the SPN has zero subscription access, a `[WARN]` line is emitted up front pointing the reader at the `Reader` grant — no more silent empty output. The idempotent-reuse check at the top also now requires `$ctx.Subscription` to be set, so stale "connected but no sub" states don't get re-used.
- 🔧 **Bug: `EntraID_APIPermissions_Catalog` + `Azure_Roles_Catalog` serialized as `[null]`.** Root cause: `Export-TieredJSON` has `-RawAPIPermissions` + `-RawAzureRoles` params, but the single caller site in `Main` never passed them — so both catalogs defaulted to empty arrays and the JSON output wrote `[null]`. The tiered arrays populated correctly because they're computed separately.
- 🔧 **Fix.** The `Export-TieredJSON` call in `Main` now passes both raw catalogs (`$apiPermissions` + `$azureRoles`). Re-run `Build_Tier_Definitions_JSON_File` on a machine with the SPN onboarded and both catalog fields populate with the full ~800 Azure role definitions and the ~1,500 enabled Graph / API permissions.
- 📚 **README § 6.1 Azure RBAC table updated** to flag the `Reader`-on-tenant-root-MG requirement explicitly for `Build_Tier_Definitions_JSON_File`, plus a NOTE explaining how to diagnose if the catalog fields still come back empty after the v2.1.175 fix.

### v2.1.174 — Promote 177 CAT samples: Custom → Locked; Locked catalog is now 180 rules

- 🆕 **All 177 Critical Asset Tagging starter samples promoted from `Custom.yaml` to `Locked.yaml`.** They now ship as part of the canonical detection catalog, force-refreshed on every Step 0 update. Total Locked CAT rules: **180** (3 original Tier-0 infra rules + 177 promoted samples across AD / Entra / Azure landing-zone / networking / workstation tiers / IoT / Azure PaaS + the `Temp-Client-Devices--excluded--SI` exclusion sample).
- 🧰 **`Custom.yaml` is now an empty customer-override scaffold.** Header comments explain how to override a Locked rule by same-stem (Custom wins on stem collision) — add rules here only when you need to override shipped logic, not as a dumping ground for new samples.
- 📚 **README teaser WOW table updated.** Dropped the "*Plus starter samples in Custom.yaml*" row; the Critical Asset detection rules count jumps from 3 → **180** to reflect the promoted content.
- 📚 **§ 6.9 Appendix regenerated** to list all 180 Locked CAT rules with tier / mode / engine columns, plus the 100 Risk Analysis reports + 2 orchestrator templates (unchanged).
- ℹ️ **Behavioural note:** the 177 promoted rules kept their original `Mode: Test` — Prod scheduled runs (`$global:Scope = @('PROD')`) still skip them silently. Customers adopt a rule by dropping a same-stem entry in `Custom.yaml` with `Mode: Prod`.

### v2.1.173 — 3-line "graph, not signatures" intro under the WOW table

- 📚 **New short paragraph right under the Locked-catalog WOW table** explains *why* 100 curated queries cover the whole attack surface: they're **graph traversals** over Microsoft Defender ExposureGraph + Azure Resource Graph, not signature-based detections. Each query follows the relationships an attacker would actually exploit (endpoint → credential → lateral → Tier-0) rather than alerting on isolated findings. Same data your SOC already pays for, framed as a graph instead of a flat list.

### v2.1.172 — Appendix § 6.9: Locked catalog — full query / rule inventory (name + purpose, each)

- 🆕 **New § 6.9 "Locked catalog — full query / rule inventory"** at the end of the Appendix. Collapsed `<details>` block following the § 6 convention, containing three tables generated directly from the shipped `DATA/*_Locked.yaml`:
  - **100 Risk Analysis reports** — `#`, `SecurityDomain`, `ReportName`, `ReportPurpose` (the one-line purpose that's already in each YAML entry), sorted by domain.
  - **2 Risk Analysis report templates** — the Summary / Detailed orchestrators that bundle multiple individual reports into one launcher run.
  - **3 Critical Asset Tagging Locked detection rules** — tag name, tier, hand-written short purpose (DomainControllerDNS, ADCertificateService, EntraSyncService).
- 🔧 **Teaser WOW table corrected** — 102 → 100 Risk Analysis queries. The earlier count was a naïve grep that included the 2 `ReportTemplates` entries; those are orchestrators, not queries. Queries + orchestrators are both listed in the new § 6.9 so the distinction is clear.
- 🧰 **TOC updated** to list § 6.9.

### v2.1.171 — README teaser: expand 'out of the box' table with AI-classified tier catalog breakdown

- 📚 **Two tables under the teaser now** instead of one:
  1. **Detection queries + tagging rules** (unchanged: 102 Risk Analysis queries, 3 CAT Locked rules, + 177 CAT Custom starter samples)
  2. **AI-classified tier catalog** — tier-by-tier counts sourced from `DATA/SecurityInsight_IdentityTiering.json`:
     - AD built-in groups: 10 / 5 / 3 / 51 → **69**
     - Entra built-in roles: 3 / 32 / 26 / 81 → **142**
     - Entra / Graph API permissions: 4 / 84 / 94 / 1,030 → **1,212**
     - Grand total: **17 / 121 / 123 / 1,162 → 1,423**
- 📚 **Azure RBAC note.** Azure role catalog ships as 0 entries because the engine classifies Azure RBAC **at run-time** against the customer's actual assignments (per subscription / RG / resource), not pre-baked — so the tier for an Azure role depends on where it's actually bound. Noted under the table.

### v2.1.170 — README teaser: at-a-glance "what you get out of the box" counts

- 📚 **New 2-row table right under the teaser** showing what ships as `Locked` content (force-refreshed on every release): **102 Risk Analysis queries** + **3 Critical Asset detection rules**. One-glance signal of how much curated KQL / ExposureGraph logic lands the moment you install.
- 📚 **Short follow-up line** mentions the 177 starter samples in CAT `Custom.yaml` (opt-in per rule via `Mode: Test` → `Prod` flip) and the AI-classified tier catalog (~69 AD groups, ~142 Entra roles, ~1,200 Graph API permissions). Context without cluttering the headline numbers.

### v2.1.169 — Ship ~177 curated sample tagging rules (all `Mode: Test`) + README guidance

- 🆕 **`SecurityInsight_CriticalAssetTagging_Custom.yaml` gains ~177 curated sample rules** covering common environment patterns that didn't have shipped Locked counterparts: Azure landing-zone subscriptions (hub platform / security / datacenter), AD / Entra identity rules, network infrastructure (backbone, distribution, access switches, WLAN, NAC, VPN, firewalls), workstation + mobile + IoT tiers, Azure PaaS resources (AKS, APIM, App Service, Functions, storage, backup, KeyVault, front door, load balancer, private endpoint, etc.), and identity classifications (GA, break-glass, krbtgt, Entra-connect sync, DCSync rights, scoped SPNs, managed identities by RBAC scope). Also includes one `Temp-Client-Devices--excluded--SI` exclusion sample.
- 🔧 **All samples ship in `Mode: Test`**, not `Prod` — every environment is different, and a sample rule that picks the right assets in tenant A may match the wrong set in tenant B. Customers are expected to evaluate each sample, tweak the KQL to fit their naming / resource conventions, then flip `Mode:` to `Prod` on the ones that belong in production. Rules they don't adopt stay on `Mode: Test` forever and are silently skipped by Prod scheduled runs (`[INFO] Skipping rule '<name>' (Mode=TEST) due to Scope filter`).
- 📚 **README § 5.6 adds an IMPORTANT call-out** at the top of the CriticalAssetTagging Mode/Scope section walking the reader through the "adopt → tweak → promote" workflow, and makes explicit that Step 0 updates never touch Custom.yaml so customer-promoted rules survive upgrades.

### v2.1.168 — CriticalAssetTagging: accept `<stem>--excluded--SI` alongside `<stem>--tier<N>--SI`

- 🆕 **New valid AssetTagName shape: `<stem>--excluded--SI`.** Used to tag assets that should appear under the "Excluded" filter in the Defender portal — typically renamed / pre-decommission machines that still linger in inventory but shouldn't count toward any tier. `Get-AssetTagStemKey` regex widened to `^(?<stem>.+?)--(?:tier(?<tier>\d+)|excluded)--SI$`. The `excluded` marker is treated as a parallel identity class: its stem is extracted the same way the tier variants are, so Custom can still override Locked by stem.
- 🔧 **Throw message updated** to name both valid shapes so future malformed entries get a clearer hint.
- 🧰 **Backward compatible.** Every existing `--tier<N>--SI` entry still matches and still produces the same stem key, so no Custom.yaml on any customer needs rewriting.

### v2.1.167 — Publish workflow: CUSTOMDATA/CUSTOMSCRIPTS safety rail no longer over-strips community-vm templates

- 🔧 **Critical publish bug.** 8 of 11 community-vm templates were being silently stripped from every community release starting with v2.1.155. Root cause: the publish workflow at `.github/workflows/publish.yml` lines 204–210 had a substring regex (`CUSTOMSCRIPTS[\\/]|CUSTOMDATA[\\/]`) meant to catch internal-only tenant paths, but the v2.1.155 SpnTenantId-missing error message legitimately includes the literal `CUSTOMDATA\SecurityInsight.custom.ps1` as a user-facing path hint. The rail matched that hint and nuked the template.
- 🔧 **Affected templates** (missing from v2.1.155 – v2.1.166 community releases): `Build_Tier_Definitions_JSON_File`, `CriticalAssetTagging`, `CriticalAssetTaggingMaintenance`, `CriticalAssetTaggingMaintenance_FixConflictingTags`, `IdentityAssetsCollectDefineTierIngestLog`, `SecurityInsight_RiskAnalysis`, `Step2_OnboardValidate-SecurityInsight-LogAnalytics`, `Step3_OnboardValidate-SecurityInsight-OpenAI-PAYG-Instance-Azure`. Step 0 couldn't refresh them from the release zip, so community-vm customers who'd installed a version *before* v2.1.155 kept running pre-v2.1.145 templates that still expected the legacy `LauncherConfig.ps1` filename and threw "LauncherConfig.ps1 not found".
- 🔧 **Fix.** Tightened the rail to only strip when `CUSTOMSCRIPTS` / `CUSTOMDATA` appears in a *programmatic path context* — i.e. preceded by a PowerShell variable (`$var\CUSTOMSCRIPTS\...`), a `Join-Path` call, or an explicit internal-only root segment (`AutomationFramework\`, `PlatformRoot\`, `AF_ROOT\`). Bare occurrences inside string literals (error messages, help text) no longer trigger the rail.
- ℹ️ **What customers need to do after this release ships.** Re-run Step 0 on the test VM (or wait for the daily scheduled task) to pick up v2.1.167 — the missing `launcher.community-vm.template.ps1` files for the 8 affected engines will come back with the Initialize-LauncherConfig pattern already in place.

### v2.1.166 — Promote Step 2 / 3 / 4 out of § 3.5.x into top-level subsections

- 🧰 **Steps get their own § 3.x slot, not a nested § 3.5.x.** Before: "Step 2 Connectivity" was buried as § 3.5.4, "Step 3 Identity infrastructure" as § 3.5.5, "Step 4 Azure OpenAI" as § 3.5.6. In the rendered TOC that made critical action items look like minor reference bullets. Now:
  - § 3.6 Step 2 — Connectivity: SPN or Managed Identity *(was § 3.5.4)*
  - § 3.7 Step 3 — Identity infrastructure: Workspace + DCE + DCR *(was § 3.5.5)*
  - § 3.8 Step 4 — Azure OpenAI (optional) *(was § 3.5.6)*
- 🔄 **Cascade renumbering** for the sections that followed:
  - § 3.9 Understand the LauncherConfig files *(was § 3.6)*
  - § 3.10 Run the Risk Analysis *(was § 3.7)*
  - § 3.11 Step 5a — Endpoint asset tagging *(was § 3.8)*
  - § 3.12 Step 5b — Azure asset tagging *(was § 3.9)*
  - § 3.13 Defender Criticality Level *(was § 3.10)*
- 🧰 **§ 3.5 stays as the pre-requisite *reference* chapter** (config-file model primer + Setup Configurator + Solution component overview). All three remaining subsections are concepts/tools, not step actions, so keeping them as § 3.5.1/3.5.2/3.5.3 is consistent.
- Anchors are clean-slug-aliased already, so no external links break from this renumber.

### v2.1.165 — Drop duplicate module pre-install loop from IdentityAssetsCollect community-vm launcher

- 🧰 **The community-vm launcher for `IdentityAssetsCollectDefineTierIngestLog` was pre-installing 5 engine-only modules** (`Az.Resources`, `Az.OperationalInsights`, `Az.Monitor`, `Az.Storage`, `AzLogDcrIngestPS`) before calling the engine. The engine's own `Ensure-SecurityInsightModules` call (at the top of the `.ps1`) already covers those, so customers saw the same module list printed **twice** — once as `[OK] module '...' present` from the launcher pre-install, and once as `[MODULE] ... present` from `Ensure-SecurityInsightModules` — with no functional purpose. Removed the 6-line `foreach` loop.
- 🧰 **Launcher still checks the 3 auth modules it actually needs** (`Az.Accounts` required, `Az.KeyVault` optional, `Microsoft.Graph.Authentication` optional) because the launcher does `Connect-AzAccount` / `Connect-MgGraph` itself during auth-resolution, BEFORE the engine starts. Those 3 pre-flights are legitimate and stay.
- 🧰 **None of the other 10 community-vm templates had this redundant loop** — the fix is scoped to the one file.

### v2.1.164 — Layer 3 `<Solution>.custom.ps1` now resolves correctly on community installs

- 🔧 **Bug fix.** On community-vm installs where `$RepoRoot` IS the solution folder, the layered-config loader was checking only the monorepo-style path `<RepoRoot>\SOLUTIONS\<Solution>\CUSTOMDATA\<Solution>.custom.ps1` — a path that doesn't exist on community layouts. Layer 3 silently skipped on every run, so any solution-wide SPN / OpenAI / SMTP values the customer put in `CUSTOMDATA\SecurityInsight.custom.ps1` (the correct community path) never loaded, and the engine threw `$global:SpnTenantId is required` even though the file was sitting right there.
- 🔧 **Fix**: `Initialize-LauncherConfig.ps1` now probes **both** paths in order: monorepo first (`<RepoRoot>\SOLUTIONS\<Solution>\CUSTOMDATA\...`), community second (`<RepoRoot>\CUSTOMDATA\...`). Whichever exists wins; when neither exists, the "absent" info log uses the layout-appropriate path so the reader knows where to drop the file.

### v2.1.163 — Collapse § 3.3 / 3.3.1 / 3.4 + all § 4.x and § 6.x subsections; add Step 1–5 markers

- 🧰 **§ 3.3 Update, § 3.3.1 Automate daily update, § 3.4 Try preview** now collapsed — heading visible, full body under a "Show details (expand)" `<details>`. Matches the pattern used in § 3.2 Install.
- 🧰 **All § 4.x and § 6.x subsections wrapped in `<details>`** so the reference chapters (4 Severity & Criticality Definitions, 6 Appendix) are scannable by heading; full content is one click away. 13 subsections total.
- 🧰 **Step 1–5 markers added to the action sections** so the chapter-3 headings align with the Step numbering used in the § 3.1 onboarding flow:
  - § 3.2 Step 1 — Install SecurityInsight (fresh machine)
  - § 3.5.4 Step 2 — Connectivity: SPN or Managed Identity
  - § 3.5.5 Step 3 — Identity infrastructure: Workspace + DCE + DCR
  - § 3.5.6 Step 4 — Azure OpenAI (optional)
  - § 3.8 Step 5a — Endpoint asset tagging
  - § 3.9 Step 5b — Azure asset tagging
- TOC updated to mirror every Step prefix.

### v2.1.162 — § 3 + § 4 readability pass: section numbers, reading order, Tier 0–3 drawing, mojibake fix

- 🆕 **§ 4.2.1 Tier 0–3 at a glance** — new mermaid drawing (added next to the criticality definitions; existing § 4.2 table untouched). Tier 0 at the top (smallest + darkest) down to Tier 3 at the bottom, so the blast-radius pyramid is visible in one look. Additive only.
- 🧰 **§ 3.5 subsections now numbered.** Three previously-unnumbered blocks inside § 3.5 got proper subsection numbers so the TOC shows them:
  - § 3.5.1 Config-file model — `.defaults.` vs `.custom.`
  - § 3.5.2 Setup Configurator
  - § 3.5.3 Solution component overview
  - § 3.5.4 Connectivity: SPN or Managed Identity *(was § 3.5.1)*
  - § 3.5.5 Identity infrastructure: Workspace + DCE + DCR *(was § 3.5.2)*
  - § 3.5.6 Azure OpenAI *(was § 3.5.3)*
- 🔀 **§ 3.6 and § 3.7 swapped.** "Understand the LauncherConfig files" (reference) now comes *before* "Run the Risk Analysis" (action). Readers see the config model in context before they're told to run the engine. Numbers and TOC updated to match.
- 🧰 **§ 5 YAML Concept subsections renumbered `6.x → 5.x`.** Left over from the earlier top-level § 6 → § 5 move — the nested subsection numbers weren't updated and collided with the `6.1–6.8` under § 6 Appendix.
- 🔧 **Mojibake fix.** Three `[⤴ Back to top]` links had been saved as double-encoded UTF-8 (bytes `c3 a2 c2 a4 c2 b4` instead of `e2 a4 b4`), rendering as `â¤´` on GitHub instead of the upward-curving arrow. Fixed in place.

### v2.1.161 — Drop the old one-line subtitle above the badges

- 📚 **Removed the old tagline blockquote** (`"Risk-based security exposure prioritization... Replace 'we have 4,000 recommendations' with 'here are the 12 things that actually matter, ranked.'"`) that sat directly under the `# 🛡️ SecurityInsight` H1. The v2.1.159 teaser block — *"Your Defender dashboard and an attacker's target list look very different..."* — already does the same job, more vividly, and sits right below the author/support line. Having both left the opening feeling repetitive.

### v2.1.159 — README teaser + expanded Introduction (session-abstract-derived copy)

- 📚 **New teaser block at the very top** (right after the author/support/watch lines). Sets up the "attacker's target list vs. Defender dashboard" hook, introduces the four scoring dimensions + ExposureGraph + AI role classification in ~150 words, and ends with the strap line *"Think like the hacker. Act like the defender. Fix what matters — first."* Adapted from the MEM26 session abstract to read as doc prose, not pitch copy.
- 📚 **§ 1 Introduction prose rewritten.** The old "Security teams are drowning / 3,000–10,000 recommendations" intro replaced with the expanded abstract — four dimensions as a bullet list, the ExposureGraph paragraph, the classification framework paragraph, and the Identity-collection paragraph (users/SPNs/MIs derived from actual permissions, new roles AI-classified automatically). Closes with a "What you'll get from this document" checklist. Risk Score formula + TIP + Outputs / Use-cases / Sample output tables kept in place.

### v2.1.158 — README overhaul: lighter § 3, stable anchors, "What's New" moved to the end

Big batch of readability fixes driven by real-user feedback on the rendered README.

**§ 3 made lighter to read**

- 📚 **§ 3.5 Pre-requisite configuration restructured.** Now leads with `.defaults.ps1` vs `.custom.ps1` primer + mermaid drawing of the 5-layer stack + Setup Configurator with PNG screenshot at the top + worked example. Previously readers scrolled through four back-to-back NOTE/TIP callouts, two duplicate onboarding tables, and a "30-second onboarding" subsection before seeing the tool that generates the config files.
- 🆕 **Setup Configurator screenshot embedded** — `DOCS/Images/SetupConfigurator-tool.png` captured headlessly from the offline HTML tool and shown inline in § 3.5.
- 🔧 **§§ 3.2, 3.3, 3.3.1 collapsed under `<details>`.** Keeps the critical copy-paste command visible; tucks parameter tables + air-gapped caveats + scheduled-task verification commands behind a one-click expander for readers who know their way around.
- 🔧 **Removed duplicate onboarding tables** (Onboarding Steps + Ingestion engines were listed twice — once in "Solution component overview", once in the old pre-requisite table).
- 🔧 **Deleted redundant "30-second onboarding" subsection** now that § 3.5 top covers the same ground more clearly.
- 🔧 **§ 3.1 cadence line fixed** — was contradicting itself ("Steps 1–4 are once-per-tenant. Step 4 runs daily/hourly"). Now explicit: Steps 2–4 once-per-tenant, Step 1 runs on updates, Step 5 (tagging) daily/hourly, Step 6 (identity) daily, Step 7 (RiskAnalysis) daily/weekly/on-demand.
- 🔧 **§ 3.1 mermaid boxes no longer truncate on GitHub render.** Labels now wrapped in `"..."` literals with explicit `<br/>` breaks so long launcher names don't overflow the box width.

**Navigation + icons**

- 🆕 **Emoji icons added to every non-definition section header.** `📘` § 1, `🧠` § 2, `🚀` § 3, `📜` § 5, `📎` § 6, `📺` § 7, `💬` § 8, `🆕` § 9, plus icons on every § 3 subsection (`📦 3.2`, `🔄 3.3`, `⏰ 3.3.1`, `🧪 3.4`, `🔧 3.5`, `🔐 3.5.1`, `🏗️ 3.5.2`, `🤖 3.5.3`, `▶️ 3.6`, `📂 3.7`, `🖥️ 3.8`, `☁️ 3.9`, `🎯 3.10`). § 4 Severity & Criticality Definitions intentionally left untouched (user-requested invariant: definitions must stay as-is).
- 🧰 **All 42 numbered `<a id="...">` anchors now have clean-slug aliases.** Every `<a id="43-asset-classification-identity">` gets a twin `<a id="asset-classification-identity">`. Internal cross-references (97 of them) switched to the clean slugs. Effect: **renumbering a chapter no longer breaks in-doc links**, and external URLs using the numbered form still resolve for backward compatibility.

**What's New moved to the end**

- 🔀 **§ 5 "What's New (v2.1.x highlights)" moved to the bottom of the doc as § 9 "What's New"** — it was wedged between the Framework and the YAML Concept on the way to Appendix, interrupting the natural read-flow. Now it's a reference section after Support. Renamed heading: dropped the "(v2.1.x highlights)" subtitle per user request. Renumbered the displaced sections: 6 → 5 (YAML), 7 → 6 (Appendix; sub-sections 7.1–7.8 → 6.1–6.8), 8 → 7 (Videos), 9 → 8 (Support). Third anchor `whats-new` added as a cleaner alias alongside the legacy `whats-new-v21x-highlights` + `5-whats-new-v21x-highlights`.

**Risk Score diagram (§ 2.2)**

- 📚 **Mermaid diagram relabelled.** `Consequence` / `Probability` changed from `1–4` to `typically 1–5 (customizable)`. `Risk Score` changed from `0–32` to `Consequence × Probability (unbounded)`. Clarification added that the shipped CSV uses 1–5 per dimension (scores 1–25) but there's no hardcoded ceiling — customers can bump the scale.

**Auth-method priority chain + error messages**

- 🔧 **Community-vm templates' missing-auth error now points at the right file.** 8 templates updated to list both `CUSTOMDATA\SecurityInsight.custom.ps1` (recommended) and `LAUNCHERS\<engine>\LauncherConfig.custom.ps1` (per-engine override) instead of the stale "set it in `LauncherConfig.ps1`" hint.
- 📚 **Priority chain (MI → KV → Cert → Secret) now explicitly documented** in README + `SecurityInsight.custom.sample.ps1` comments, including the cross-layer override gotcha ("certificate at Layer 1 wins over secret at Layer 3 — null out the higher-priority field if you want the lower-priority one").

**Component overview ("What's in the box")**

- 🔀 **Moved out of the early intro** (where it interrupted the talk-track) and into § 3.5 as the "Solution component overview". Regrouped into two sub-tables (Onboarding Steps in order vs Ingestion engines on a schedule). Step 4 (Power BI dashboard) now included — was missing from the old flat list.

### v2.1.157 — README: move "What's in the box" into § 3.5 as "Solution component overview"

- 📚 **The per-component table that used to sit near the top of the README (after the intro and talk-track) is now the first subsection of § 3.5 Pre-requisite configuration.** That's where readers are actually deciding which launcher to run first, so putting the component inventory there avoids a scroll-back. Rows are regrouped into two sub-tables:
  - **Onboarding Steps** (run once per tenant, in order) — Step 1 / 2 / 3 / 4, plus the two one-time provisioners (`Setup-SecurityInsight-CustomSecurityAttributes`, `Build_Tier_Definitions_JSON_File`)
  - **Ingestion engines** (run on a schedule) — `SecurityInsight_RiskAnalysis`, `IdentityAssetsCollectDefineTierIngestLog`, `CriticalAssetTagging` (+ maintenance siblings)
- 📚 **Step 4 (Power BI dashboard) now listed in the overview** alongside the other Steps — previously "What's in the box" predated Step 4 and didn't include it.

### v2.1.156 — Document auth-method priority chain + cross-layer override gotcha

- 📚 **README § 3.5 now documents the priority chain explicitly.** The launcher picks the FIRST auth method whose fields are populated — regardless of which config layer set them:
  1. Managed Identity  (`$global:UseManagedIdentity = $true`)
  2. SPN + Key Vault secret  (`$global:SpnKeyVaultName + $global:SpnSecretName`)
  3. SPN + certificate  (`$global:SpnCertificateThumbprint`)
  4. SPN + plaintext secret  (`$global:SpnClientSecret`)
- 📚 **New IMPORTANT call-out explains the cross-layer override gotcha.** If your tenant-level `platform-defaults.ps1` (Layer 1) ships `$global:SpnCertificateThumbprint` and your `SecurityInsight.custom.ps1` (Layer 3) adds `$global:SpnClientSecret`, **certificate wins** — it's higher in the priority chain. "Closer layer wins" applies at the *variable* level, but the *method* is chosen by the priority table. To force a lower-priority method, null out the higher-priority field in the closer layer.
- 📚 **`SecurityInsight.custom.sample.ps1` auth section now reprints the same priority chain + override example**, so anyone copying the sample sees the gotcha without cross-referencing the README.

> **No code change** — the chain (MI → KV → Cert → Secret) was already coded in every regular community-vm template; this release only documents it.

### v2.1.155 — Better `$global:SpnTenantId is required` error + README promotes solution-wide `SecurityInsight.custom.ps1` for auth

- 🔧 **Community-vm templates' missing-auth error now points at the right file.** The old message said "set it in `LauncherConfig.ps1`" (legacy filename). The new multi-line error explicitly names both options in the layered model:
  - `CUSTOMDATA\SecurityInsight.custom.ps1` — solution-wide, recommended; covers every SI engine
  - `LAUNCHERS\<engine>\LauncherConfig.custom.ps1` — per-engine override; closest wins
  …and it points the reader at the matching `.sample.ps1` + README § 3.5. Applied to 8 community-vm templates (Build_Tier_Definitions, CriticalAssetTagging, CriticalAssetTaggingMaintenance, CAT_FixConflictingTags, IdentityAssetsCollectDefineTierIngestLog, RiskAnalysis, Step2, Step3).
- 📚 **README § 3.5 now has a ⭐ TIP recommending `SecurityInsight.custom.ps1` for shared auth.** Motivation: most customers want to paste their SPN once and have all ~10 SI engines inherit it, not maintain a separate `LauncherConfig.custom.ps1` per engine. The per-engine override file is still documented for the rare case where one engine needs a different value.

### v2.1.154 — Config snapshot: readable, only values from the 5-6 layered config files

- 🔧 **Snapshot no longer dumps "Layer 0 — pre-existing" globals.** The previous release captured every `$global:*` already in session before the initializer ran (leaks from `$PROFILE`, a prior launcher run in the same PS host, parent scripts). In practice this meant ~150 unrelated variables — large arrays like `$Exposure_Reports` (9 × ~25 KB of inline KQL) and `$RiskDefinitions` — made the log unreadable. Only variables set by the 5-6 layered config files are captured now:
  1. `platform-defaults.ps1` (tenant, internal only)
  2. `<Solution>.shared-defaults.ps1` (solution baseline)
  3. `<Solution>.custom.ps1` (solution-wide customer)
  4. `LauncherConfig.defaults.ps1` (per-engine baseline)
  5. `LauncherConfig.custom.ps1` (per-engine customer, closest wins)
  6. derived (initializer fallback step)
- 🔧 **Large values are now truncated.** Strings > 200 chars, arrays > 3 elements, and hashtables > 5 keys are summarized with `[truncated, N total chars]` / `[N elements total]` / `@{ N keys: k1, k2, ... }` markers so one run's log is a few KB instead of hundreds of KB.
- 🔧 **Simpler layout.** Two sections only:
  1. **Per-layer grouping** — platform / solution / engine layers in precedence order, each with source file path + its contributed variables.
  2. **Aggregated alphabetical** — one line per variable: `$global:Foo  [L2 shared-defaults]  = value` (name + winning layer + value). The "winner" view customers want for "where does `$global:Foo` actually come from?".
- 🧰 **Dropped the "Value change history" middle section** and the trailing redaction disclaimer. Less noise; the two remaining sections carry the same information.

### v2.1.153 — Config snapshot writes to the **solution's** `DATA\LOGS\` on internal-mode monorepo installs

- 🔧 **Snapshot path now resolves to `<RepoRoot>\SOLUTIONS\<Solution>\DATA\LOGS\`** when the monorepo layout is detected, falling back to `<RepoRoot>\DATA\LOGS\` for community installs where `$InstallPath` IS the solution root.
- **Problem this fixes:** on an internal-vm deploy running from `C:\SCRIPTS\AutomateIT\`, `$InstallPath` resolves to the monorepo root, so snapshots landed in `C:\SCRIPTS\AutomateIT\DATA\LOGS\` — alongside unrelated artifacts from other solutions — instead of `C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\DATA\LOGS\` next to the solution's other `DATA\` content. Community deploys already landed in the right place because for them `$InstallPath` == solution root. Both layouts now converge on the solution-scoped path.

### v2.1.152 — Config snapshot adds value-change history + aggregated summary + source file paths

- 🧰 **Per-layer section now lists the source file path** right under the layer header. Each layer's contributions are auditable without cross-referencing the trail at the top.
- 🆕 **New "Value change history" section.** For every variable touched by more than one layer, shows the full chain:
  ```
  $global:DceName
      [Layer 2 - shared-defaults]              = dce-securityinsight
          file: C:\...\launchers\_lib\SecurityInsight.shared-defaults.ps1
      [Layer 5 - LauncherConfig.custom]        = dce-securityinsight  [no-op: value unchanged by this layer]
          file: C:\...\launchers\CriticalAssetTagging\LauncherConfig.custom.ps1
  ```
  The `[no-op: value unchanged by this layer]` marker flags the case where a later override wrote the same value — useful for diagnosing "why didn't my override do anything?" (because it set the same value that was already there).
- 🆕 **New "Aggregated effective configuration (alphabetical)" section at the end.** Flat alphabetical list of every `$global:*` with its final effective value + winning layer + full path of the file that set it. The "what did the engine actually see" view customers ask for.

### v2.1.151 — Config snapshot lists every `$global:*` **assigned** per layer (AST-parsed)

- 🧰 **Every layer's snapshot section now includes every `$global:Foo = ...` the layer's `.ps1` file assigned**, not just the values that changed. Previous versions used value-diff only — so if Layer 2 set `$DceName = 'dce-securityinsight'` and Layer 5 later re-assigned it to the SAME value, Layer 5's touch was invisible. This mattered for debugging "why did my Layer 5 override not take effect?" cases: now you see the assignment under Layer 5 even when it was a no-op, making "closer wins" behaviour auditable.
- 🧰 **How it works:** PowerShell AST parser walks each layer file and extracts every `[AssignmentStatementAst]` whose Left is `$global:*`. Union with the prior value-diff logic catches both literal assignments AND dynamic sets (`Set-Variable -Scope Global`, function side-effects). Any touched variable gets attributed to the latest-touching layer in the provenance map, preserving the existing "last wins" semantics.

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

### v2.1.133 — Drop stale `AD_GroupMembership` key from tiering JSON output

- 🧰 **`SecurityInsight_IdentityTiering.json` no longer carries the dead `AD_GroupMembership` key.** The consumer side in `IdentityAssetsCollectDefineTierIngestLog` was stripped earlier (see `# AD_GroupMembership JSON snapshot is no longer used.` comment on its line 1441) but the producer kept emitting it, leaving a `"AD_GroupMembership": [null]` stub in every regenerated catalog. The AI tiering prompt path that reads AD group membership (`-ADGroupMembership` param on the tiering function) is unchanged — members are still fed to the AI as classification context; we just don't persist the snapshot.

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

