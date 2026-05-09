# Release notes for SecurityInsight

## v2.2.160

Latest 30 commits touching SOLUTIONS/SecurityInsight/ in the upstream monorepo monorepo:

- release: SecurityInsight v2.2.160 - Port-V1Platform ACL self-repair (1060e3f4)
- release: SecurityInsight v2.2.159 - Setup-Unattended -SkipPlatformDefaults switch (67eb293a)
- release: SecurityInsight v2.2.158 - Port-V1Platform.ps1 always overwrites (0a169aaa)
- release: SecurityInsight v2.2.157 - v1->v2 bridge cert-auth + PS 5.1 unattended (d0f968da)
- release: SecurityInsight v2.2.156 - Port-V1Platform + Test-PlatformConnect auto-detect V2Root (7a3afd4f)
- release: SecurityInsight v2.2.155 - Sync-AutomateIT-Engine auto-Unblock-File (c17fd9ee)
- release: SecurityInsight v2.2.154 - Port-V1Platform + Test-PlatformConnect (bbc0e783)
- release: SecurityInsight v2.2.153 - drop legacy AutomateIT_InstallUpdate refs (3cda6e1e)
- release: SecurityInsight v2.2.152 - Update-SecurityInsight.ps1 one-liner updater (6624ab59)
- release: SecurityInsight v2.2.151 - unattended setup + Internal/Community flavours (dae40cd9)
- release: SecurityInsight v2.2.150 - install guides for git + Azure CLI (4914f51b)
- release: SecurityInsight v2.2.149 - Bootstrap-ContainerAppJob.ps1 no longer hardcodes dev path (0c6be29a)
- release: SecurityInsight v2.2.148 - schedule examples in US 12-hour format (4be7b06d)
- release: SecurityInsight v2.2.147 - pre-flight: detect PS module presence + scope (8c065edc)
- release: SecurityInsight v2.2.146 - pre-flight: Az PS + Mg + az CLI in ONE block (33ea07db)
- release: SecurityInsight v2.2.145 - launch pre-flight: az CLI is a HARD block (d7ced97a)
- release: SecurityInsight v2.2.144 - launch pre-flight surfaces az CLI status (076189c1)
- release: SecurityInsight v2.2.143 - Phase 0 pre-flight: az CLI + login check before Phase 1 (a75f39f3)
- release: SecurityInsight v2.2.142 - Step 8: Setup button to top + 'Apply' -> 'Setup Infrastructure' (9ebac462)
- release: SecurityInsight v2.2.141 - wizard Phase 5 provisions Container Apps Job runtime (017afc75)
- release: SecurityInsight v2.2.140 - chapter 3 diagram redesigned for readability (dfc6ab78)
- release: SecurityInsight v2.2.139 - README S4 restructure + screenshots + scheduling + legacy cleanup (dae64158)
- release: SecurityInsight v2.2.138 - README Prerequisites: full module set + AllUsers scope (88dcbb92)
- release: SecurityInsight v2.2.137 - docs catch-up + 4.1 phases as headers (ea7b2b5c)
- release: SecurityInsight v2.2.136 - Phase 4 creates Entra Diagnostic Setting (ef946223)
- release: SecurityInsight v2.2.135 - _GrantRbac filters inherited assignments (b00bcd30)
- release: SecurityInsight v2.2.134 - wizard grants Contributor + forces SI_UseStorageOAuth (43004c62)
- release: SecurityInsight v2.2.133 - don't leak SMTP/OpenAI when operator picked Off (009923d4)
- release: SecurityInsight v2.2.132 - wizard Phase 3 fix for null sub-properties (99d66665)
- release: SecurityInsight v2.2.131 - hotfix _Step regression in wizard pre-flight (cd3edf7d)

---

# Release notes — SecurityInsight v2.2

> **Curated changelog**. The publish workflow auto-prepends the last 30 commits from the upstream monorepo as a raw activity log; this file is the human-friendly narrative on top.

---

## v2.2.160 — `Port-V1Platform.ps1`: ACL self-repair before write

New "Phase 0" runs `takeown /F <folder> /R /A` + `icacls <folder> /grant USERNAME:(OI)(CI)F /T` + `icacls <folder> /grant Administrators:(OI)(CI)F /T` on both target folders (`SOLUTIONS\PlatformConfiguration\config\` + `SOLUTIONS\SecurityInsight\config\`) before writing `platform-defaults.ps1` / `Connect_Azure.ps1` / `setup-unattended.json`. Also clears any `IsReadOnly` attribute on existing files in the tree.

Fixes the case where `Sync-AutomateIT.ps1` ran elevated and created the folders owned by SYSTEM/admin, then a regular-shell re-run of the porter hit `Access denied`. Self-heals when run elevated; silent no-op (with `[WARN]`) when not elevated, falling through to let the actual write surface a real error if perms still block it.

---

## v2.2.159 — `Setup-SecurityInsight-Unattended.ps1`: `-SkipPlatformDefaults`

New switch lets the operator pre-load v1 platform globals (via their own `connect.ps1` that imports `2LINKIT-Functions.psm1` + `Automation-ConnectDetails.psm1` + `Automation-DefaultVariables.psm1` + dot-sources `Connect_Azure.ps1`) and tell Setup-Unattended to skip its own dot-source of `platform-defaults.ps1`. Sanity-checks `$global:HighPriv_Modern_CertificateThumbprint_Azure` to ensure the operator actually ran the connect script before passing the switch.

```powershell
. .\connect.ps1                                  # operator's manual v1 connect
.\Setup-SecurityInsight-Unattended.ps1 -SkipPlatformDefaults
```

Cleanest path for FVF-style customers who already have a working v1 connect chain and don't want Port-V1Platform.ps1 to re-derive everything.

---

## v2.2.158 — `Port-V1Platform.ps1`: drop `-Force`, always overwrite

`-Force` is gone. Old behavior backed up `platform-defaults.ps1` + `Connect_Azure.ps1` to `.bak.<timestamp>` before overwrite unless `-Force` was passed; that meant operators had to remember to pass `-Force` to skip cruft accumulation, and re-running the porter would slowly fill the config folder with timestamp-suffixed copies. New behavior is the simpler model: the v1 source files are the truth, the v2 generated files are caches; re-running just overwrites in place. No backups, no flag.

The v1 input is never touched, and the porter itself ships from a versioned repo, so there's no real backup-recovery scenario the old `-Force`-default-off behavior was protecting against.

---

## v2.2.157 — Internal v1->v2 bridge: cert-auth wiring + PS 5.1 unattended setup

Three fixes that together make `Setup-SecurityInsight-Unattended.ps1` work on a fresh internal customer VM out of the box.

**`Setup-SecurityInsight-Unattended.ps1` — drop PS 7 hard requirement.** Was `#Requires -Version 7.0`; orchestrator + all 5 backend cmdlets parse clean on 5.1 with zero PS 7-only features (`??`, `?.`, `ForEach-Object -Parallel`, `ConvertFrom-Json -AsHashtable` all absent). Now `#Requires -Version 5.1`. PS 7 is still optional; the only place it's mandatory is `container/*.ps1` (Linux container hosts).

**`Setup-SecurityInsight-Unattended.ps1` — set `$global:AutomationFramework = $true` before dot-sourcing `platform-defaults.ps1`.** v1's `Connect_Azure.ps1` + `Default_Variables` branch on this flag for cert-based unattended auth vs interactive. Without it, the cert path is never taken and `$global:HighPriv_Modern_CertificateThumbprint_Azure` stays `$null`, which blows up `Connect-AzAccount -CertificateThumbprint` at Phase 0. Also acts as a safety net for `platform-defaults.ps1` files generated by older `Port-V1Platform.ps1` versions.

**`Port-V1Platform.ps1` — preserve `function Default_Variables { ... }` wrapper + invoke it.** Previous "strip wrapper" behaviour broke v1 files where assignments inside the function used bare `$HighPriv_*` (no `$global:` prefix) — extracting them to script scope kept them script-scoped instead of global. Now the function is preserved verbatim and invoked once at dot-source time, exactly the boot order v1 itself uses. Generated `platform-defaults.ps1` also pre-sets `$global:AutomationFramework = $true` before invoking + before the `Connect_Azure.ps1` dot-source.

---

## v2.2.156 — `Port-V1Platform.ps1` + `Test-PlatformConnect.ps1`: auto-detect V2Root

Both internal helpers used to default `-V2Root` to a hardcoded `C:\AutomateIT`, which broke for installs on any other drive (D:\, E:\, network share). They now auto-detect V2Root from `$PSScriptRoot` (three folders up — script lives at `<V2Root>\SOLUTIONS\PlatformConfiguration\INTERNAL\`), so they always target the install they were launched from regardless of drive letter. `-V2Root` override still works for the rare cross-install case.

---

## v2.2.155 — `Sync-AutomateIT-Engine.ps1`: auto-unblock copied scripts

After the zipball extract, the engine now runs `Unblock-File` recursively across `*.ps1,*.psm1,*.psd1,*.dll,*.exe` under every synced solution's `SOLUTIONS\<Name>\` tree. Files downloaded from GitHub carry a `Zone.Identifier` ADS that triggers `RemoteSigned` execution-policy refusal — this strips it as part of the sync, so launchers and engines run without "file is blocked, operator must Unblock-File first" friction.

Internal-only change (engine lives under `INTERNAL/` and is scrubbed from public mirrors). Community-edition operators are unaffected.

---

## v2.2.154 — Internal migration tooling: `Port-V1Platform.ps1` + `Test-PlatformConnect.ps1`

Two new internal-only helpers under `SOLUTIONS\PlatformConfiguration\INTERNAL\` (scrubbed from public mirrors by the publish workflow). They cut the FVF-style v1→v2 customer onboarding from ~30 min of manual file copies + ad-hoc smoke tests down to two commands.

**`Port-V1Platform.ps1`** — one-shot v1→v2 platform port. Reads `<V1ROOT>\FUNCTIONS\Automation-DefaultVariables.psm1`, strips the `function Default_Variables() { ... }` wrapper, writes the body verbatim to `SOLUTIONS\PlatformConfiguration\config\platform-defaults.ps1`, copies `Connect_Azure.ps1` alongside it, and appends the dot-source line so `$global:HighPriv_Modern_*` + `$global:Context` + `Get-PlatformSecret` load with one `. platform-defaults.ps1`. Also drops the `setup-unattended.json` template into the SI config folder when missing. Idempotent, backs up existing files to `.bak.<timestamp>`, supports `-DryRun` and `-Force`.

**`Test-PlatformConnect.ps1`** — read-only end-to-end smoke test of the `$global:AutomationFramework = $true` bridge. Seven phases: dot-source → globals contract check → bridge mirrors → `Connect-AzAccount -ServicePrincipal -CertificateThumbprint` → `Connect-MgGraph -ClientId -CertificateThumbprint` → `Get-PlatformSecret` KV pull → PASS/FAIL summary with exit code. Skip flags: `-SkipMgGraph`, `-SkipKv`, `-KeyVaultProbeName`. Replaces the manual `pwsh -NoProfile -Command { ... }` one-liner that operators had to assemble from `Onboarding.txt`.

Run order on a new internal customer VM:

```powershell
cd C:\AutomateIT\SOLUTIONS\PlatformConfiguration\INTERNAL
.\Port-V1Platform.ps1 -V1Source <V1ROOT>     # port + drop json
.\Test-PlatformConnect.ps1                   # smoke test, exit 0 = green

cd C:\AutomateIT\SOLUTIONS\SecurityInsight
.\Setup-SecurityInsight-Unattended.ps1       # actual deploy
```

Community-edition operators see none of this — `INTERNAL/` is excluded by the publish workflow.

---

## v2.2.153 — Drop legacy `AutomateIT_InstallUpdate` references in active code

Three engine / launcher files carried comments referencing the old `AutomateIT_InstallUpdate.ps1` name from the early bootstrap layout. Rewrote the comments to reference whichever updater the operator uses (no specific tool name), so the comments stay accurate as the bootstrap layer evolves:

- `tools\Run-AllEngines.ps1` — the "skip git pull" hint when the install isn't a git clone now points at the generic `Sync-AutomateIT.ps1` / `Update-SecurityInsight.ps1` pair instead of the obsolete name.
- `launcher\_lib\Get-PublishedVersion.ps1` — comment about why the per-solution `VERSION` file wins over root `VERSION.txt` no longer name-checks a specific updater.
- `engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1` — comment about why PTC writes to `.custom.json` (so it survives updates) no longer name-checks a specific updater.
- `engine\asset-profiling\shared\IdentityCatalogTierComputer.ps1` — same comment cleanup, generic "(or whichever updater)" wording.

No code behaviour changes. Comments-only.

`RELEASENOTES.md` and `README.md` historical entries still mention `AutomateIT_InstallUpdate.ps1` — those are the changelog and the "What's New" table; they describe past state and are intentionally left as-is.

---

## v2.2.152 — `Update-SecurityInsight.ps1` — one-liner updater

New top-level script alongside `README.md` and `Setup-SecurityInsight.ps1`. Pulls the latest stable release and prints the version delta. Replaces the old "`cd <repo> && git pull`" muscle memory with a single command + sanity checks + readable output.

```powershell
cd C:\SecurityInsight
.\Update-SecurityInsight.ps1                       # git pull, report version delta
.\Update-SecurityInsight.ps1 -ShowReleaseNotes     # also dump curated entries since your old version
```

What it does:

1. Verifies `git` is on PATH. If missing, prints the canonical Git for Windows installer block (matches the README § 4 Prerequisites install snippet).
2. Verifies the current folder is a `git clone` of `KnudsenMorten/SecurityInsight`. Warns (doesn't block) if the `origin` URL doesn't match — handy for forks.
3. Captures `VERSION` + `git rev-parse --short HEAD` for the before-pull state.
4. Runs `git pull --ff-only origin main` — fast-forward only, never merges. If the local has diverged (you committed local edits to tracked files), the pull fails cleanly and the script prints the canonical `git stash` workaround.
5. Captures the new `VERSION` + commit, prints the delta (`v2.2.149 → v2.2.152, commit abc123 → def456`) or "already on latest".
6. With `-ShowReleaseNotes`, dumps every `## v…` block from `RELEASENOTES.md` between your old and new versions so you see exactly what changed without opening the file.
7. Closes with a "what's next" reminder — re-launch the Setup Wizard only if you crossed a major release boundary; scheduled engines pick up new code on their next cycle without manual action.

`config\SecurityInsight.custom.ps1` and per-engine `LauncherConfig.custom.ps1` files are gitignored — your customer-specific values + secrets are never touched by this update.

---

## v2.2.151 — Unattended setup: `Setup-SecurityInsight-Unattended.ps1` + Internal/Community flavours

The HTML wizard (`setup\ConfigWizard\Start-SetupWizard.ps1`) is great for first-time community installs but is a poor fit for the migration use case where a customer already has a v1 platform layer (cert-based SPN, KV, `$global:HighPriv_Modern_*` globals, `Automation-DefaultVariables.psm1`). For migration the operator wants to: re-use the v1 cert SPN, dot-source the ported `platform-defaults.ps1`, render a **bridged** `SecurityInsight.custom.ps1` that references the v1 globals via `$global:AutomationFramework=$true` — none of which the GUI wizard does.

**New top-level script** `SOLUTIONS\SecurityInsight\Setup-SecurityInsight-Unattended.ps1` covers it. Reads `config\setup-unattended.json` (+ optional CLI overrides), connects via cert (Internal flavour) or relies on the operator's `Connect-Az`/`Connect-Mg` (Community flavour), and runs the same Phase 1-5 chain the HTML wizard does — just sequentially, no browser.

**Two flavours, one script.**

- **Internal** (FVF-style migration): re-uses the existing v1 cert-based SPN, dot-sources `platform-defaults.ps1`, calls `New-SISpn -UseExistingAppId` to top up Graph perms only (no new app reg, no new cred), renders `Write-SICustomConfig -Mode Bridged` (no secrets in the file — references `$global:HighPriv_Modern_*` + `$global:AutomationFramework=$true`). Connects to all 3 surfaces (Az PS / Mg / az CLI) using the v1 cert in `LocalMachine\My`. No operator interaction.
- **Community**: standalone install, no v1 platform layer. Creates a new SI SPN, renders the existing inline `SecurityInsight.custom.ps1`. Operator must `Connect-AzAccount` + `Connect-MgGraph` first (same as the GUI wizard's contract).

**JSON-driven config** lives at `config\setup-unattended.json` (gitignored — the customer-owned working copy) with a sample at `config\setup-unattended.sample.json`. Six functional sections: `Flavour` / `Sub` / `Resources` / `Auth_Internal` / `Auth_Community` / `EntraDiag` / `Container`. `null` everywhere = "use script default or platform-defaults global". Every JSON value has a matching CLI switch for one-off overrides:

```powershell
.\Setup-SecurityInsight-Unattended.ps1                                   # reads JSON, defaults
.\Setup-SecurityInsight-Unattended.ps1 -EntraDiag_Enabled                # one-off override
.\Setup-SecurityInsight-Unattended.ps1 -Flavour Community                # flavour override
.\Setup-SecurityInsight-Unattended.ps1 -ConfigPath D:\customers\acme.json  # multi-customer admin VM
```

**Two backend cmdlet edits enable this:**

- **`New-SISpn.ps1`** — new `-UseExistingAppId` + `-ExistingAppId` + `-ExistingThumbprint` parameters. When set, the cmdlet looks up the SP by AppId (instead of by DisplayName), skips `New-MgApplication`, skips cred generation. The existing Graph-perms-grant + Azure-RBAC blocks run as-is (already idempotent — already-granted perms are no-ops). `DisplayName` and `CredStorage` become optional in this mode (looked up from the existing app reg).
- **`Write-SICustomConfig.ps1`** — new `-Mode <Inline|Bridged>` parameter (default `Inline` keeps the existing wizard behaviour). When `Bridged`, the SPN section emits `$global:SI_SPN_AppId = $global:HighPriv_Modern_ApplicationID_Azure` etc. and a new section 11 renders the `Get-PlatformSecret` late-binding for `SI_StorageKey` / `SI_Shodan_ApiKey` / `OpenAI_apiKey`. The customer file holds **zero secrets** — everything resolves at engine load time via the v1 platform layer.

**Idempotent re-run.** Every backend cmdlet already handles "already in place" / "already granted" cases. Schedule the unattended script in VisualCron daily and it self-heals if anything drifted.

**Files in this release:**

| Path | Status | Purpose |
|------|--------|---------|
| `SOLUTIONS\SecurityInsight\Setup-SecurityInsight-Unattended.ps1` | **NEW** | The unattended setup tool |
| `SOLUTIONS\SecurityInsight\config\setup-unattended.sample.json` | **NEW** | Public-repo template the operator copies |
| `SOLUTIONS\SecurityInsight\setup\ConfigWizard\backend\New-SISpn.ps1` | edit | `-UseExistingAppId` / `-ExistingAppId` / `-ExistingThumbprint` mode |
| `SOLUTIONS\SecurityInsight\setup\ConfigWizard\backend\Write-SICustomConfig.ps1` | edit | `-Mode <Inline\|Bridged>` parameter + bridged SPN section + KV-pull footer |

The HTML wizard (`Start-SetupWizard.ps1`) is unchanged — community + new-customer onboarding still uses it, no breaking change.

---

## v2.2.150 — Install guides for git + Azure CLI (wizard pre-flight + README §4)

Two new install sections under § 4 Prerequisites + matching expansion of the wizard pre-flight remediation block. Both use the same direct-download-MSI/EXE pattern (no winget dependency — works on stock Windows Server images that don't have the App Installer pre-installed).

**`Azure CLI` sub-section.** New 3-line MSI install:

```powershell
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi
Start-Process msiexec.exe -Wait -ArgumentList '/I', 'AzureCLI.msi'
```

Same commands now mirrored into the wizard's pre-flight `[BLOCKED]` block — when `Azure CLI: NOT INSTALLED`, the operator sees copy-paste-ready PowerShell instead of just a documentation URL. `aka.ms/installazurecliwindows` is Microsoft's official redirector to the latest MSI (no version pinning), and `$ProgressPreference = 'SilentlyContinue'` makes `Invoke-WebRequest` ~30× faster on Windows PowerShell 5.1.

**`Git for Windows` sub-section.** Required for the § 4.2 `git clone` + the `git pull` update path; stock Windows Server images don't ship with `git`. Install command resolves the latest Git for Windows release URL via the GitHub API (no version pinning), filters to the 64-bit standard installer (skipping `PortableGit*` / `MinGit*` artefacts), downloads, and runs Inno Setup unattended:

```powershell
$ProgressPreference = 'SilentlyContinue'
$gitUrl = ((Invoke-RestMethod 'https://api.github.com/repos/git-for-windows/git/releases/latest').assets |
    Where-Object { $_.name -like '*-64-bit.exe' -and $_.name -notlike 'PortableGit*' -and $_.name -notlike 'MinGit*' } |
    Select-Object -First 1).browser_download_url
Invoke-WebRequest -Uri $gitUrl -OutFile .\GitInstaller.exe
Start-Process .\GitInstaller.exe -Wait -ArgumentList '/VERYSILENT','/NORESTART','/NOCANCEL','/SP-'
```

Both sections close with the *"close + reopen PowerShell so PATH picks up the new binary"* reminder — the most common gotcha after a fresh install.

Docs / wizard text only — no functional changes to the install flow itself.

---

## v2.2.149 — Critical fix: `Bootstrap-ContainerAppJob.ps1` no longer hard-codes the dev tree path

User report: clicked Setup Infrastructure with `azureContainerMI` host, watched Phases 1-4 run cleanly (SPN + workspace + storage + EntraDiag all created), then Phase 5 immediately threw:

```
C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\config\SecurityInsight.custom.ps1 not found -- run Bootstrap-Auth.ps1 first
```

Root cause: `Bootstrap-ContainerAppJob.ps1` line 93 hard-coded the customer config path to `C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\config\SecurityInsight.custom.ps1` — that's the upstream **dev tree** location, not the customer's `C:\SecurityInsight\config\…`. Every customer install would hit this immediately.

**Fix:** resolve the customer config relative to the script's own location (`$PSScriptRoot`), with a CWD fallback for invocations from other directories. Now works for:

- Customer installs at `C:\SecurityInsight\` → reads `C:\SecurityInsight\config\SecurityInsight.custom.ps1`.
- Dev tree at `C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\` → reads the same dev-tree path it always did.
- Operator runs `.\Bootstrap-ContainerAppJob.ps1` from a different CWD → falls back to `<cwd>\config\SecurityInsight.custom.ps1` if the script-relative path doesn't exist.

Error message also updated to point at the **Setup Wizard's Phase 3** (the canonical way to generate the file in v2.2) instead of the legacy `Bootstrap-Auth.ps1`.

This was a regression from v2.2.105's repo restructure — the dev-tree path got committed, customer installs were never tested. Live test on `C:\SecurityInsight\` now reproduces the failure on v2.2.148; should pass on v2.2.149.

---

## v2.2.148 — Schedule examples: 12-hour US format (3 PM / 9 PM / 1 AM)

The § 4.4.1 (VM scheduling) and § 4.4.2 (Container Apps Job KEDA cron) tables previously used 24-hour times (`15:00 / 18:00 / 21:00 / 01:00 / 03:00`) with `≈18:00 CET` European-local approximations. Switched to **12-hour AM/PM format** for the VM table:

- 3:00 PM — git pull
- 6:00 PM — Privilege Tier Classifier
- 9:00 PM — 4 profilers in parallel
- 1:00 AM — Risk Analysis Summary
- 3:00 AM — Risk Analysis Detailed

Same daily cadence — just a label change. The `schtasks` example keeps `21:00` since `/ST` only accepts 24-hour `HH:MM`, with a comment noting "9 PM is `21:00`" so the operator can map between the two.

For the cron table (always UTC), shifted the default hours to assume **US Eastern** as the operator timezone (`0 22 * * *` for 6 PM EST etc.) and added explicit "= 6:00 PM EST / 3:00 PM PST"-style annotations + a footnote explaining cron is UTC and to shift for non-US-Eastern teams.

Docs only — no code changes.

---

## v2.2.147 — Pre-flight: also detect PS module presence + scope (AllUsers vs CurrentUser)

User feedback: *"do you also check for the proper ps module like az and graph and az cli. otherwise it must guide user to install in allusers"*. The previous pre-flight verified the connection contexts (`Connect-AzAccount` + `Connect-MgGraph`) but assumed the underlying modules were already installed. If `Az.Accounts` or `Microsoft.Graph.Authentication` weren't on disk at all, the operator saw "NOT CONNECTED" with no hint that the actual fix was `Install-Module`. And if installed only at `CurrentUser` scope, the wizard worked for the interactive operator but the engines (running as SYSTEM / service account / Container Apps Job MI) couldn't see the modules at runtime.

Pre-flight now probes each module via `Get-Module -ListAvailable` + path inspection:

- **Module path under `$env:ProgramFiles\…\Modules`** → AllUsers scope (engines visible, **OK**).
- **Module path under `$HOME\Documents\…\Modules`** → CurrentUser scope (warned — engines won't see it).
- **No path returned** → not installed (blocked).

The unified `[BLOCKED]` block now shows **5 status lines** when any prerequisite is missing:

```
Az PowerShell module    : NOT INSTALLED
Microsoft.Graph module  : 2.x (Scope=CurrentUser -- engines run as SYSTEM and CANNOT see CurrentUser modules)
Az PowerShell context   : NOT CONNECTED
Microsoft Graph context : NOT CONNECTED
Azure CLI               : 2.76.0 installed but NOT LOGGED IN
```

…with the corresponding install/connect commands emitted in order. The remediation banner now also calls out the elevation requirement: *"Run these in an ELEVATED PowerShell window (Run as Administrator)"* + the rationale (engines run as SYSTEM and need AllUsers-scoped modules).

When everything's green, the success banner shows 5 `[OK]` lines (modules + contexts + CLI) so the operator can confirm scope at a glance:

```
[OK]   Az PS module   : 5.x.x (Scope=AllUsers)
[OK]   MgGraph module : 2.x.x (Scope=AllUsers)
[OK]   Az context     : ...
[OK]   Graph context  : ...
[OK]   Azure CLI      : ...
```

This matches the README §4 Prerequisites (v2.2.138) which already documented the `-Scope AllUsers` requirement; the wizard now enforces it at launch.

---

## v2.2.146 — Pre-flight: Az PS + Mg + Azure CLI checks unified into ONE block

User feedback on v2.2.145 hard block: the existing Az PS / Microsoft Graph blocked-banner fired BEFORE the new Azure CLI check ran, so an operator missing both Mg and `az login` only saw the Mg instruction — they fixed Mg, re-launched, then hit the `az login` block separately, then re-launched again. *"no difference. i need it to say that i need to login with az cli — how hard is it to understand. it doesn't mention it."*

Merged the three pre-flight checks (Az PowerShell, Microsoft Graph, Azure CLI) into **one unified block**. When ANY of the three is missing, the operator gets:

- A single `[BLOCKED]` banner showing all three states at once (per-line green/yellow status).
- A single "Run these in THIS shell, then re-launch" command list — only the missing pieces are emitted, in the right order.
- A single throw to abort startup.

Example output for an operator missing Mg + `az login` (Az PS already connected):

```
[BLOCKED] /api/apply needs Az PowerShell + Microsoft Graph + Azure CLI contexts.

    Az PowerShell  : mok@2linkIT.net (sub: Partner Subscription MCPP (PAYG))
    Microsoft Graph: NOT CONNECTED
    Azure CLI      : 2.76.0 installed but NOT LOGGED IN

  Run these in THIS shell, then re-launch the wizard:

    Connect-MgGraph -TenantId f0fa27a0-... -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.ReadWrite.All' -NoWelcome
    az login --tenant f0fa27a0-...
    .\Start-SetupWizard.ps1
```

One banner, one re-launch. The duplicate stand-alone Azure CLI block from v2.2.144/145 has been removed (its checks moved into the unified block). The `/api/apply` Phase 0 enforcement (v2.2.143) remains as defence-in-depth.

---

## v2.2.145 — Wizard launch pre-flight: Azure CLI is now a HARD block

`v2.2.144` made the `az` CLI check a soft warning so VM-only operators wouldn't be blocked. User feedback during live test: *"no difference. make it hard"*. The hard block is the right call — every SI deployment that touches Container Apps needs `az` CLI, and even VM-only deployments benefit from having it ready (the operator probably has it installed already if they're doing Azure work; the friction of installing `az` once is much lower than the friction of re-launching the wizard mid-flow).

The `az` CLI section in `Start-SetupWizard.ps1` pre-flight now matches the Az PowerShell / Microsoft Graph / binary-compat checks: same `[BLOCKED]` red banner, same "fix and re-launch" remediation block, same `throw` to abort startup. The HttpListener never binds, the browser never opens, until `az version` returns a parseable version AND `az account show` returns a logged-in account.

Two distinct error variants:

- **Not installed:** `[BLOCKED] Azure CLI (az) is not installed or not on PATH.` + install URL + `az login --tenant <id>` + `.\Start-SetupWizard.ps1`.
- **Installed but not logged in:** `[BLOCKED] Azure CLI <ver> is installed but NOT LOGGED IN.` + `az login --tenant <id>` + `.\Start-SetupWizard.ps1`.

The `/api/apply` Phase 0 check (v2.2.143) remains as defence-in-depth — if anything changes between launch and clicking Setup (e.g. operator runs `az logout` in another terminal), the apply still refuses to run and no half-deployed Azure resources are left behind.

---

## v2.2.144 — Wizard launch pre-flight now also surfaces `az` CLI status (soft warning)

User feedback on v2.2.143: the `az` CLI / `az login` check fired only at `/api/apply` time, after the operator had already filled in 8 wizard pages. By then it was too late to fix the gap without a full re-run. The launch pre-flight already validated Az PowerShell + Microsoft Graph + Az binary-compat — it should also surface the `az` CLI state up-front so the operator can fix it before clicking Next.

Added an `az` CLI section to `Start-SetupWizard.ps1` pre-flight, immediately after the Az binary-compat smoke test. Outputs:

- **Az CLI installed + logged in:** `[OK] Azure CLI : 2.76.0 (signed in as mok@…, sub …)`
- **Az CLI installed but not logged in:** `[WARN] Azure CLI: 2.76.0 installed but NOT LOGGED IN. (Only required if Step 1 = 'Azure Container Apps Job with MI'.)` + `[WARN] Run: az login --tenant <id>`
- **Az CLI not installed:** `[WARN] Azure CLI: NOT INSTALLED.` + install URL + `az login` command

**Soft warning, not a block.** At launch time the wizard doesn't yet know which engine host the operator will pick on Step 1. VM-host operators (the 95% case) don't need `az` CLI at all, so blocking the launch on missing `az` would be over-restrictive. The hard requirement is still enforced at `/api/apply` Phase 0 (v2.2.143) — but by the time the operator gets there, they've seen the warning and either installed `az login` or knowingly chosen a host that doesn't need it.

This complements the existing pre-flight chain: Az PowerShell context → Microsoft Graph context → Az binary-compat smoke test → **Az CLI status** → listener up.

---

## v2.2.143 — `/api/apply` Phase 0 pre-flight: fail before Phase 1 if az CLI / az login missing

User report from live test: clicked Setup Infrastructure with `azureContainerMI` host selected, watched Phases 1–4 succeed (SPN created, workspace + DCE + storage created, custom config written, Entra Diag Setting created), then **Phase 5 failed at the `az account show` check** with `ERROR: Please run 'az login' to setup account`. The 4 prior phases left orphan resources in the tenant — the operator now has a half-deployed SI install they have to either complete by running `az login` + re-clicking Setup, or roll back manually.

**New Phase 0 pre-flight in `/api/apply`.** Runs **before** Phase 1 (SPN creation). Today's checks fire only when `hostType === 'azureContainerMI'` (since VM-host runs don't need az CLI):

1. **`az` CLI installed.** `az version` must return a parseable JSON with `azure-cli` field. If not: clear remediation message naming the install URL, the exact `az login --tenant <id>` to run, and the alternative ("change Step 1's engine host to a VM option to skip Phase 5 entirely").
2. **`az` CLI logged in.** `az account show` must return a JSON with `id`. If `LASTEXITCODE != 0` or the JSON parse fails: clear remediation message naming the exact `az login --tenant <id>` to run.
3. **`az` CLI sub matches the wizard's target sub.** When the operator's `az` context is on a different subscription than what they typed in Step 2, `az account set --subscription <id>` is invoked. If that fails (sub not visible to the account): clear remediation message naming both the manual `az account set` and the `az login` fallback.

If any check fails, `/api/apply` returns `{ok:false, phase:'preflight', error:…}` immediately — **no SPN, no workspace, no storage, no Diag Setting created**. The operator fixes the gap and re-clicks Setup; idempotent re-run works because nothing was provisioned.

VM-host operators (the 95% case) see no behaviour change — Phase 0 short-circuits the moment it sees `hostType !== 'azureContainerMI'`.

This complements the existing wizard-launch pre-flight checks for Az PowerShell context + Microsoft Graph context + Az binary-compat smoke test. All four pre-checks now share the same "fail fast with clear remediation, never leave half-deployed resources" contract.

---

## v2.2.142 — Step 8 layout: Setup button moved to top, "Apply" → "Setup Infrastructure"

UI feedback from live test on the Apply page:

- **Setup button moved above the "What will happen" summary card.** Operators reviewing the per-phase summary previously had to scroll past 5 phase cards before reaching the action button. Now the button is the first thing in the page body — review summary is below for reference.
- **"Apply" → "Setup Infrastructure"** everywhere on Step 8: card heading, button label, page title, eyebrow ("Step 8 of 8 · Review & Setup"), page lead. The new label more accurately describes what the button does (provisions Azure infrastructure) and avoids the ambiguous verb "Apply".

Docs only — no backend changes.

---

## v2.2.141 — Wizard Phase 5: Container Apps Job runtime provisioned in /api/apply

The wizard's UI had a Step 1 "engine host + bootstrap auth" dropdown with **Azure Container Apps Job with system-assigned MI** as one of the three host options, but `/api/apply` only ran 4 phases (SPN / Infra / Config / EntraDiag). When the operator picked the container option and clicked Setup, the SPN + workspace + storage + diag setting got built — but **no ACR, no Container Apps Environment, no Jobs**. The container infra had to be provisioned by a separate manual `Bootstrap-ContainerAppJob.ps1` invocation. Reported by user during live test: *"i dont see the container jobs + infra to be build"*.

**New Phase 5** in `/api/apply`:

- New backend cmdlet `setup\ConfigWizard\backend\Initialize-SIContainerInfra.ps1` — thin wrapper around the canonical `Bootstrap-ContainerAppJob.ps1` at the repo root.
- Pre-flight: verifies `az` CLI is on PATH and logged in to the same subscription Phase 2 used (`az account show`). Fails fast with a clear remediation message if either check fails (`az login --tenant <id>` is the fix).
- Sets `$global:SI_Bootstrap_ResourceGroupName / Location / AcrName / EnvName` so Bootstrap-ContainerAppJob's existing layered-config resolver picks them up — no rewrite of the 725-line bootstrap script.
- Invokes `Bootstrap-ContainerAppJob.ps1` with `-UseManagedIdentity -UseKEDA -KedaMaxReplicas 30` defaults.
- Captures resource IDs post-run via `az acr show`, `az containerapp env show`, `az containerapp job list` and returns them in the `/api/apply` response (`container.AcrLoginServer`, `container.EnvResourceId`, `container.Jobs[]` with name + engine + cron).

**Gating.** Phase 5 only fires when `state.hostType === 'azureContainerMI'` (the operator picked the container option on Step 1). VM hosts get `phaseStatus.container = 'skipped'` with a clear log line — no spurious ACR creation for operators who never asked for containers.

**Wizard UI** updated:

- 5th progress card on the Apply page (Phase 5 — Container Apps Job runtime).
- 5th summary block above the Setup button explaining what Phase 5 will do (and that it requires Owner / RBAC Admin + `az login`).
- The summary renders "SKIPPED" when the operator picked a VM host on Step 1 (vs hidden) so it's obvious the wizard knows about the option but isn't acting on it.

**Idempotent.** Bootstrap-ContainerAppJob's per-resource existence checks short-circuit when ACR / CAE / Jobs already exist, so re-running `/api/apply` after a partial failure resumes cleanly — same idempotency contract the other 4 phases already have.

**Pre-requisites** the operator needs (clearly surfaced as pre-flight errors, not silent failures):

1. `az` CLI installed (https://learn.microsoft.com/cli/azure/install-azure-cli-windows).
2. `az login --tenant <tenant-id>` in the same shell as the wizard.
3. Owner OR Contributor + User Access Administrator on the target subscription (creating the system-assigned Managed Identity + assigning RBAC needs `Microsoft.Authorization/roleAssignments/write`).

---

## v2.2.140 — Chapter 3 Inputs / Enrichment / Outputs diagram redesigned for readability

The mermaid flowchart at the top of § 3 grouped 7 inputs + 4 enrichment items + 7 outputs into 3 nested subgraphs, each with one node per item — 18 individual nodes converging on a single tiny `CORE` node, edges from every subgraph member to `CORE`. On GitHub's renderer this came out cramped: text inside small boxes, edges overlapping, the engine box illegible.

Redesigned to **4 large boxes** in a single horizontal row: `INPUTS` → `ENGINES` ← `ENRICHMENT`, `ENGINES` → `OUTPUTS`. Each input/enrichment/output is now a line of text inside the box (instead of its own node), so the diagram fits on one screen, every label is readable at default zoom, and the visual hierarchy maps to the section headers (`§ 3.1 Inputs`, `§ 3.2 Enrichment`, `§ 3.3 Outputs`) below. Engine box rendered as a circle to differentiate from the rectangular IO boxes, with thicker stroke. Solid `==>` arrows for required dataflow, dotted `-.->` for optional enrichment.

Docs only — no code changes.

---

## v2.2.139 — README §4 restructured: numbered Get/Auth/Run sub-sections, screenshots, scheduling guide

Major README pass. Aggregates several user requests:

**Numbered sub-section headers** for the quick-start steps so each is scannable + linkable on its own:

- **§ 4.2 Get the code** (was *Step 1*) — `git clone … 2>$null` + `cd C:\SecurityInsight` (suppresses non-fatal stderr on re-run, lands you in the tree). Brief "Update to latest version" sub-block: just `cd` + `git pull`.
- **§ 4.3 Authenticate, then launch the Setup Wizard** (was *Step 2*).
- **§ 4.4 Run the engines** (was *Step 3*) + 3 new sub-sections (4.4.1–4.4.3) on scheduling.

**Embedded wizard screenshots.** The previous "wizard tour" table is now a per-step walkthrough with **14 screenshots** under `docs/screenshots/wizard/`: launch + welcome + connect-error, the 8 wizard pages (1 Connect, 2 Workspace, 3 Mail, 4 CMDB, 5 OpenAI, 6 Shodan, 7 Diagnostic logs + Defender JSON, 8 Setup), each with a paragraph of what to do on the page.

**§ 4.4.1 Schedule the engines on a VM (Windows Task Scheduler).** Daily cadence table with the production timing:

- 15:00 — `git pull` (Update SecurityInsight)
- 18:00 — Privilege Tier Classifier *(only if Azure OpenAI is enabled)*
- 21:00 — 4 asset profilers in parallel (Identity / Endpoint / Azure / Public IP) — separate scheduled tasks, same start time, no cross-locking
- 01:00 — Risk Analysis Summary
- 03:00 — Risk Analysis Detailed

Plus the launcher-flavour reference (`internal-vm` for production, `community-vm` for community / public, planned `community-azure`) and a `schtasks /Create` example with the `SecurityInsight\<n>. <task name> (<HH:MM>)` naming convention.

**§ 4.4.2 Schedule the engines on Azure Container Apps Job (KEDA auto-scaling).** Producer-worker shard pattern, 1 replica per ~50 queue messages, 6 jobs (4 profilers + tier classifier + 2 RA), each with its own cron schedule on the Container Apps Job resource itself (no external Task Scheduler).

**§ 4.4.3 VM vs Container Apps Job — recommendation.** Default to VM; move profiling-only to KEDA when any of (single-engine wall-clock > 2h, no long-running VM, want scale-to-zero) hits. Hybrid mode (profiling on KEDA, RA + Tier Classifier on VM) for medium-large estates. Explicit *don't run everything on containers just because you can* — RA + Tier Classifier are aggregations, not parallelizable scans.

**§ 4 chapter restructure + legacy cleanup.** The old §§ 4.2–4.12 (High-level overview, preview, pre-req config, Connectivity, Identity infrastructure, Azure OpenAI, LauncherConfig, Run RA, Distribution, engine catalog, Container & KEDA host-mode) restructured to §§ 4.5–4.11 *minus* 4 wizard-superseded sections that were removed entirely:

- **4.5 High-level overview** — legacy mermaid showing pre-wizard `Bootstrap-Auth.ps1` → `Bootstrap-Storage.ps1` → `Bootstrap-ContainerAppJob.ps1` flow. The Setup Wizard now does all of this in one click.
- **4.7.2 Setup Configurator** — legacy offline HTML form that pre-dated the new Setup Wizard. Wizard fully replaces it.
- **4.7.3 Solution component overview** — legacy v2.1 component naming (`Validate-SIPermissions_OnboardValidate-SecurityInsight-Permissions`, `IdentityAssetsCollectDefineTierIngestLog`, `CriticalAssetTagging`) that doesn't match v2.2's actual layout. Auth-method priority chain referenced old globals (`$global:UseManagedIdentity`, `$global:SpnClientId`) instead of the v2.2 `$global:SI_SPN_*` names.
- **4.8 Connectivity — SPN or Managed Identity** — pre-wizard manual auth setup. Wizard's Phase 1 handles all of this.
- **4.9 Identity infrastructure — Workspace + DCE + DCR** — pre-wizard manual infra setup. Wizard's Phase 2 handles all of this.
- **4.12 Run the Risk Analysis** — duplicated content already covered in § 4.4.
- The legacy "Step 3 — Step 10" walkthrough (manual config copy → Bootstrap-Auth → Bootstrap-Storage → optional Bootstrap-ContainerAppJob → LauncherConfig copy → run profilers → run RA → verify) was the entire pre-wizard onboarding flow. Replaced by the **§ 4.4.4 Fine-tuning via sample files** sub-section (small reference table pointing to the 3 sample files for advanced edits) + **§ 4.4.5 Verify outputs** + **§ 4.4.6 When something doesn't work**.

TOC updated to match. In-body refs to `§ 4.3` (preview), `§ 4.12` (KEDA), `§ 4.15` (KEDA), `§§ 4.3 – 4.5` (asset classification — actually chapter 5) all corrected.

**§ 4.1.1 Updating to the latest version** simplified to the 2-line `cd` + `git pull` form per user feedback.

Docs only — no code changes.

---

## v2.2.138 — README Prerequisites: complete PowerShell module set + PS-5.1 vs pwsh-7 split

The Prerequisites section listed only `Az` + `Microsoft.Graph`, missing **6 of 8** modules SI actually needs at engine runtime. New operators following the prereq list as-is would have engine runs fail on the first `Search-AzGraph` (no `Az.ResourceGraph`), `Export-Excel` (no `ImportExcel`), `ConvertFrom-Yaml` (no `powershell-yaml`), or DCR ingest (no `AzLogDcrIngestPS`).

**Now documented in §4 Prerequisites:**

- Full 8-module set as a table with source + which surface (wizard / engines) uses each: `Az`, `Az.ResourceGraph`, `Microsoft.Graph`, `Microsoft.Graph.Beta`, `AzLogDcrIngestPS`, `MicrosoftGraphPS`, `ImportExcel`, `powershell-yaml`.
- Note that `Az.ResourceGraph` is **NOT** part of the `Az` meta-module — needs separate install. Easy to miss.
- The `Ensure-SecurityInsightModules` auto-installer pattern: every engine calls it at startup, so a fresh VM with stock PS + Internet auto-bootstraps on first launcher run. Documented as the recommended path.
- One-line manual `Install-Module` for operators who want to seed the box upfront or work air-gapped — **scoped `AllUsers`, not `CurrentUser`**, because engines run unattended under `NT AUTHORITY\SYSTEM` (Scheduled Tasks), service accounts, or Container Apps Job MIs that can't see `CurrentUser`-scoped modules. `Ensure-SecurityInsightModules` already defaults to `AllUsers`.
- **PowerShell version split** clarified: wizard runs on **pwsh 7+** (HttpListener + Az.Accounts 5.0+ SecureString marshaling); engines run on **Windows PowerShell 5.1** as the canonical runtime (engines also run on pwsh 7, but published behaviour targets 5.1).
- Phase 4 operator-role requirement (Security Administrator OR Global Administrator at tenant scope) added to the Azure/Entra prerequisites — `aadiam` is tenant-scoped, subscription Owner is not sufficient.

Docs only — no code changes.

---

## v2.2.137 — Docs catch-up for v2.2.131 → v2.2.136 + § 4.1 phases broken out as headers

Documentation drift sweep covering everything the last 6 releases changed:

**README.md § 4.1** — the wizard walkthrough's phase summary was a 3-row table; now broken out as **4 standalone sub-section headers** (`Phase 1 — Service principal`, `Phase 2 — Infrastructure`, `Phase 3 — Config file`, `Phase 4 — Entra ID Diagnostic Setting`) so each phase is scannable on its own. Phase 2 description now correctly lists `Contributor` + `Log Analytics Contributor` on the workspace and `Contributor` + `Monitoring Metrics Publisher` on the DCR resource group (per v2.2.134), and notes that `$global:SI_UseStorageOAuth = $true` is auto-written into the rendered custom file. Phase 4 is brand new and documents the Entra Diagnostic Setting flow + the `Security Administrator` / `Global Administrator` operator role requirement.

**README.md § 4 wizard tour Step 8** — was "Review summary (3 phase cards). Click ▶ Setup. Watch SPN → Infrastructure → Config phases turn green." Now reads "4 phase cards" + adds Entra Diagnostic Setting to the phase chain + mentions the Diagnostic Setting PUT result in the per-step log description.

**README.md § 4.1 Azure RBAC role assignments list** — added two new bullets matching v2.2.134:
- `Contributor` at the workspace (in addition to `Log Analytics Contributor`)
- `Contributor` at the DCR resource group (in addition to `Monitoring Metrics Publisher`)

**`Setup-SecurityInsight.html`** — the Apply page progress tracker had only 3 `<div class="apply-phase">` divs (spn / infra / config). Added a 4th for `data-phase="entraDiag"` so the live progress UI shows all four phases (the summary cards above were already updated in v2.2.136 but the live tracker below wasn't).

**`config\SecurityInsight.custom.sample.ps1`** — the commented-out `$global:SI_UseStorageOAuth = $true` line now has a header comment noting that the Setup Wizard auto-writes this into the rendered custom file (v2.2.134+), so the commented line in the sample is illustrative-only.

**`setup\ConfigWizard\README.md`** — `/api/apply` flow now mentions `Set-SIEntraDiagnosticSetting` as the 4th step in the chain, the response shape now lists `entraDiag` alongside `spn`/`infra`/`configFile`, and the backend cmdlets file-layout listing now includes `Set-SIEntraDiagnosticSetting.ps1`.

No code changes in this release — docs only.

---

## v2.2.136 — Wizard Phase 4: Entra ID Diagnostic Setting created on Setup (default ON)

The wizard's `entraDiagToSI` toggle in the UI was wired through to a config-only flag (`$global:SI_AutoCreateEntraDiagToSelf`) that **no engine code consumed** — meaning even with the toggle enabled, no Diagnostic Setting was ever created in Azure. Sign-in / audit logs never landed in the SI workspace, and RA queries that correlate sign-in risk against Tier-0 assets returned empty. Reported by the user during live tenant test.

**New Phase 4** in `/api/apply` now creates the tenant-level Diagnostic Setting in code:

- New backend cmdlet `setup/ConfigWizard/backend/Set-SIEntraDiagnosticSetting.ps1`
- PUTs to `https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/SI-EntraDiag?api-version=2017-04-01`
- 8 categories enabled by default: `SignInLogs`, `AuditLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs`, `ManagedIdentitySignInLogs`, `UserRiskEvents`, `ProvisioningLogs`, `MicrosoftGraphActivityLogs`
- Targets the SI workspace ResourceId from Phase 2 output (`infraOut.WorkspaceResourceId`)
- Idempotent — PUT replaces the named setting, leaves other settings (e.g. an existing Sentinel-side one) untouched
- AuthorizationFailed on the `aadiam` provider scope is surfaced with a clear remediation: the operator running the wizard needs Entra **Security Administrator** OR **Global Administrator** at tenant scope. Subscription-level Owner is **not** sufficient — `aadiam` diagnosticSettings are tenant-scoped, not ARM-scoped.

**Default flipped to ON.** `entraDiagToSI` was previously `'off'` by default. Operators expected the toggle to be on automatically (you can't have an SI deployment with no sign-in logs landing anywhere). Now defaults to `'enabled'`. Auto-skipped when the operator linked an existing Defender / Sentinel workspace via `defenderMode='linked'` (the linked workspace's existing Diagnostic Setting already streams the same categories).

**Phase status reporting.** The `/api/apply` response now includes `phaseStatus.entraDiag` with values `pending` / `ok` / `failed` / `skipped`, plus an `entraDiag` output object on success (`Name`, `WorkspaceResourceId`, `Categories`, `Url`). The Apply page UI shows a 4th summary card "Phase 4 — Entra ID Diagnostic Setting".

After upgrading: re-run the wizard's `/api/apply`. You'll see `phase=entraDiag start ... [OK] Entra Diagnostic Setting 'SI-EntraDiag' created / updated`. Verify in Azure portal: **Entra ID → Monitoring → Diagnostic settings → SI-EntraDiag** — should show all 8 categories streaming to your SI workspace.

---

## v2.2.135 — `_GrantRbac` existence check now filters out inherited assignments

`v2.2.134` added the workspace + DCR-RG `Contributor` grants but the `_GrantRbac` function's existence check was matching inherited assignments, so the explicit child-scope grant was being skipped on every re-run.

`Get-AzRoleAssignment -ObjectId X -Scope <child>` returns assignments AT or ABOVE the child scope — meaning a Contributor inherited from a parent (e.g. an existing RG-level grant from a previous run) showed up when probing the workspace scope, the function logged `RBAC 'Contributor' already in place at /…/resourceGroups/<rg>` and returned early. The workspace itself never received an explicit Contributor assignment, so the engine's own role-existence probe (which is stricter — it filters on `.Scope -eq` the target) kept warning `could not grant 'Contributor' on workspace`.

**Fix:** post-filter the `Get-AzRoleAssignment` result with `Where-Object { $_.Scope -ieq $Scope }`. Now only direct assignments at exactly the target scope count as "already in place"; inherited assignments are ignored and the function creates the explicit child-scope assignment the engine wants.

After upgrading, re-run the wizard's `/api/apply` once. You'll see two new `[OK] RBAC 'Contributor' granted at …workspaces/<ws>` and `…resourceGroups/<rg>` lines, and the engine's warnings will go away.

---

## v2.2.134 — Wizard SPN: add `Contributor` on workspace + DCR RG + force `SI_UseStorageOAuth`

Three runtime-warning fixes the live engine surfaced after a clean v2.2.133 wizard run:

**1. `Contributor` added at the LA workspace.** The engine self-heals its own RBAC every run by probing each role assignment and warning when one is missing. It expects `Contributor` (in addition to `Log Analytics Contributor`) at the workspace scope. The wizard previously only granted LA Contributor, so every engine run logged:

```
WARNING: could not grant 'Contributor' on workspace: AuthorizationFailed ...
```

`Initialize-SIInfra` now also assigns the built-in `Contributor` role (`b24988ac-6180-42a0-ab88-20f7382dd24c`) at the workspace. LA Contributor stays — the two roles together are the engine's expectation.

**2. `Contributor` added at the DCR resource group.** Same pattern as #1, same warning text but at RG scope. The engine wants Contributor + Monitoring Metrics Publisher; the wizard previously only granted MMPub. Both now assigned.

**3. `$global:SI_UseStorageOAuth = $true` written into `SecurityInsight.custom.ps1`.** The engine's storage path probes `Get-AzStorageAccountKey` first and falls back to OAuth when the key fetch fails. The SPN has `Storage Blob/Table/Queue Data Contributor` (data-plane only) — it does **not** have `Microsoft.Storage/storageAccounts/listKeys/action`, which is a control-plane permission only `Storage Account Contributor` or full `Contributor` on the storage account would grant. The probe failed every run with:

```
WARNING: Prestage: storage key fetch failed: Forbidden
WARNING: 'sistaging' container ensure failed: Forbidden
WARNING: 'securityinsight' container ensure failed: Forbidden
```

even though the engine's downstream OAuth code path would have worked. Setting `SI_UseStorageOAuth = $true` skips the listKeys probe entirely; the engine goes straight to AAD-based blob ops, where the existing data-plane RBAC roles cover create-container + read/write.

**Net effect:** clean engine run with no Forbidden / AuthorizationFailed warnings on a fresh wizard install. Existing v2.2.131-133 deployments need either a) re-run wizard `/api/apply` (idempotent — adds the missing role assignments + rewrites custom config), or b) two manual `New-AzRoleAssignment -RoleDefinitionName 'Contributor'` calls + an edit to `SecurityInsight.custom.ps1` to add the new flag.

---

## v2.2.133 — Wizard config render: don't leak SMTP/OpenAI sections when the operator turned them off

`Write-SICustomConfig.ps1` was emitting the full SMTP block — `$global:SendMail = $true` plus the default port and TLS settings — even when the operator had set SMTP mode to **Off** in the wizard. Same hazard for the Azure OpenAI section. The Shodan and CMDB sections already gated on meaningful content (`$Shodan.ApiKey`, `$Cmdb.Enabled`), so they were unaffected.

**What was happening:** the wizard's persisted state could carry a stale `smtp` object from a prior session where the operator briefly toggled SMTP on. Even after toggling back to Off, the object remained in state with all fields null. `ConvertTo-HashtableFromPso` (now correctly returning a non-null hashtable for empty inputs after the v2.2.132 `[AllowNull()]` fix) handed a defaulted-but-empty hashtable to `Write-SICustomConfig`. The `if ($Smtp)` check passed on hashtable presence alone and the SMTP scaffolding rendered with `$global:SendMail = $true` — silently turning mail back on for that customer.

**Fix:** matched the Shodan/CMDB pattern. SMTP now requires `$Smtp.Server`; OpenAI now requires `$OpenAi.Endpoint`. Without those, the section is meaningless and is skipped entirely.

If you've already run the wizard with v2.2.131 or v2.2.132 and SMTP turned off, re-render the config (or delete the stray SMTP block from `config\SecurityInsight.custom.ps1`) — otherwise `$global:SendMail = $true` is set in your file and the engine will try to send mail with no server configured.

---

## v2.2.132 — Wizard Phase 3 fix: `ConvertTo-HashtableFromPso` rejects null sub-properties

The Setup Wizard's `/api/apply` Phase 3 (config render) was failing with:

```
✗ Apply failed at phase: config
Cannot bind argument to parameter 'InputObject' because it is null.
```

even when the SPN and Infrastructure phases had completed successfully. SPN + Infra succeeded because they consume their hashtable args directly, but Phase 3 first runs the wizard's own `ConvertTo-HashtableFromPso` over the optional state pages (SMTP, Azure OpenAI, Shodan, CMDB) to convert the JSON-deserialized `PSCustomObject` tree to splattable hashtables. The conversion crashed before `Write-SICustomConfig` ever ran.

**Root cause:** `ConvertTo-HashtableFromPso` declared its parameter as `[Parameter(Mandatory)] $InputObject` without `[AllowNull()]`. PowerShell's parameter binder rejects `$null` at *binding time* — before the function body runs — so the line-61 null guard (`if ($null -eq $InputObject) { return $null }`) was unreachable for explicit-call cases. When the recursion at `$h[$p.Name] = ConvertTo-HashtableFromPso $p.Value` hit a property whose value was `$null` — for example an unfilled optional SMTP `User` field, an OpenAI `MaxTokens` left blank, or a CMDB `RefreshHours` not set — the recursive call threw the `Cannot bind argument…` error.

**Fix:** added `[AllowNull()]` to the parameter declaration so the function's existing null guard can do its job. Behavior unchanged for non-null inputs; null inputs now correctly return `$null` instead of crashing the entire `/api/apply` call.

This blocked any operator who didn't fill every single optional field on every wizard page. Now SMTP-only, OpenAI-only, or CMDB-disabled deployments render their config cleanly.

---

## v2.2.131 — Hotfix: wizard fails to start with `_Step is not recognized` regression

`v2.2.130` introduced an Az binary-compat smoke test in `Start-SetupWizard.ps1` pre-flight, but called `_Step` — a helper that exists in the backend cmdlets (`Initialize-SIInfra.ps1`, `New-SISpn.ps1`) but **not** in the listener script itself. The listener only defines `_Info`, `_Ok`, `_Warn`, `_Err`. As a result, every `v2.2.130` wizard launch failed at line 247 with:

```
The term '_Step' is not recognized as the name of a cmdlet, function, script file, or operable program.
```

before the smoke test could run, before the HttpListener could bind, before the operator could even open the wizard UI. Hard block.

Fix: replaced `_Step "verify Az PowerShell binary-compat..."` with `_Info ...`. The smoke test logic itself is unchanged — it still runs `Get-AzAccessToken` and gates wizard startup on the Az.Identity.Broker mismatch markers documented in `v2.2.130`. Only the helper-call typo is corrected.

Recommend everyone on `v2.2.130` upgrade to `v2.2.131` — the previous tag is unusable.

---

## v2.2.130 — README: strip broken wizard screenshots + reformat permissions tables as lists + Az.Identity.Broker workaround note

Three doc fixes:

**1. Wizard tour table — broken `![](png-path)` markdown stripped.** The 9-row screenshot walkthrough table referenced PNG files that don't exist yet on the public repo (only the capture-list does). GitHub rendered the missing images as broken-link icons. Stripped the third "Screenshot" column entirely; replaced with a callout pointing to `docs/screenshots/wizard/README.md` for the planned filenames. When PNGs land in a follow-up tag the image refs go back in.

**2. Permissions section — 3 wide tables converted to lists.** The Microsoft Graph permissions table (13 rows × 2 cols) was readable but the Azure RBAC table (9 rows × 4 cols of long content) and the Managed Identity table both overflowed reasonable viewports. Backtick'd role names ("`Storage Blob Data Contributor`") wrapping in narrow cells produced a visual mess (each backtick'd word stacked on its own line). Converted all three tables to bulleted lists — same content, no clipping, no awkward stacking. Also promoted the 5 sub-section headers from `#####` (h5, renders too subtly on GitHub) to `####` (h4) so they read as proper section dividers.

**3. New troubleshooting note for `Az.Identity.Broker` SharedTokenCache exception** that surfaces during Setup on some pwsh shells:

> `Method not found: 'Void Azure.Identity.Broker.SharedTokenCacheCredentialBrokerOptions..ctor(Azure.Identity.TokenCachePersistenceOptions)'.`
>
> This is a side-loaded-assembly version mismatch between Az.Accounts and the Azure.Identity.Broker extension in the listener's pwsh process. The wizard's `Register-AzResourceProvider` calls (and Connect-AzAccount internally) bubble it up as "Your Azure credentials have not been set up". **Fix in your interactive shell:**
> ```powershell
> Update-Module Az -Force        # bring all Az.* sub-modules to consistent versions
> # Close the pwsh window entirely (the broken assembly state lives in-process)
> # Open a fresh pwsh, re-do Connect-AzAccount + Connect-MgGraph, re-launch the wizard
> ```

**4. Wizard pre-flight now smoke-tests Az binary-compat upfront.** The Az.Identity.Broker mismatch above used to surface mid-Phase-2 (Setup phase 1 SPN succeeded since it only uses Microsoft.Graph; Phase 2 infra failed on the first Az PS call). `Start-SetupWizard.ps1` now runs `Get-AzAccessToken -ResourceUrl 'https://management.azure.com/'` as a smoke test during pre-flight, right after the Az + Graph context checks. If the call throws with any of the known mismatch markers (`Method not found`, `Azure.Identity`, `SharedTokenCache`, `credentials have not been set up`), the wizard refuses to start with a clear remediation message:

```
[BLOCKED] Az PowerShell assemblies in this pwsh process are binary-incompatible.

   Symptom : <the actual exception message>

  This is a known side-loaded-assembly version mismatch between Az.Accounts
  and the Azure.Identity.Broker extension. The wizard's /api/apply would fail
  mid-Phase-2 on the first Az PowerShell call. Fix in your interactive shell:

    Update-Module Az -Force
    # Then close THIS pwsh window entirely (the broken assemblies live in-process)
    # Open a fresh pwsh, re-run Connect-AzAccount + Connect-MgGraph, re-launch the wizard.
```

Operators no longer waste 5+ minutes clicking through the wizard, watching Phase 1 succeed, then hitting the same error in Phase 2.

---

## v2.2.129 — README §3 docs: fix TOC anchor + Mermaid parse error + readability of §3.1 inputs table

Three doc-only fixes from live testing:

**1. TOC link "4. How to Implement" was jumping to §3.** A stale `<a id="how-to-implement-quick-start"></a>` anchor was sitting two lines ABOVE the §3 heading (left over from a prior section renumbering). Clicking the §4 TOC entry hit that orphan first → browser scrolled to ~§3 territory, not the actual §4 heading. Removed the stale anchor block (kept the legitimate one at the actual §4 heading).

**2. Mermaid flowchart in §3 failed with parse error.** The diagram nodes for ENRICH had unquoted parens in their labels:
```
E2[Azure OpenAI<br/>(role/permission tiering)]
E3[Customer .custom.yaml<br/>(per-rule overrides + adds)]
E4[Shodan<br/>(public-IP exposure)]
```
Mermaid parses `(` inside `[...]` as the start of a stadium-shape token, throwing `Expecting 'SQE', 'DOUBLECIRCLEEND', ...`. Fix: wrap each label in double quotes per Mermaid syntax for special chars:
```
E2["Azure OpenAI<br/>(role/permission tiering)"]
E3["Customer .custom.yaml<br/>(per-rule overrides + adds)"]
E4["Shodan<br/>(public-IP exposure)"]
```
The diagram now renders cleanly on GitHub.

**3. §3.1 "Inputs — supported data providers" table reformatted as a list.** The previous 4-column table (`Provider | What | Engine | Required?`) overflowed every reasonable viewport on GitHub — the rightmost "Required?" column was clipped on screens narrower than ~1900 px because GitHub's Markdown→HTML doesn't add horizontal scroll. Converted to a bulleted list with the same content (provider name + status emoji as the bullet lead, what-it-gives-us as the body, *Read by:* annotation in italics underneath). Reads cleanly at any width and the structure preserves all the original info (no content lost).

No code changes — pure docs fixes. Customers cloning fresh from `main` see a working TOC, a rendering Mermaid diagram, and a readable §3.1 inputs section.

---

## v2.2.128 — Setup Wizard: handle Az.Accounts 5.0+ SecureString tokens for DCE REST PUT

Live test on the v2.2.127 DCE REST fallback got further but failed with:

```
DCE REST PUT failed for dce-securityinsight-4 :
{"error":{"code":"InvalidAuthenticationToken","message":"The access token is invalid."}}
```

**Root cause:** Az.Accounts 5.0+ changed `Get-AzAccessToken` to return the bearer token as a `System.Security.SecureString` instead of a plain string. PowerShell's `"Bearer $token"` interpolation on a `SecureString` produces the literal string `"Bearer System.Security.SecureString"` — ARM rejects it with `InvalidAuthenticationToken`.

**Fix:** `Initialize-SIInfra.ps1`'s DCE REST PUT now type-checks the returned token and marshals via BSTR when it's a SecureString:

```powershell
$tokenObj = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop
$token = $tokenObj.Token
if ($token -is [System.Security.SecureString]) {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
    try { $token = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
```

Backwards-compatible: older Az.Accounts versions returning a plain string flow straight through. The BSTR is zero-freed in `finally` so the plain-text token doesn't linger in memory longer than necessary.

This is the fix for any future REST call we add to the wizard backend (Diagnostic Setting creation, KV creation when Initialize-SIInfra learns to make KVs, etc.) — same pattern applies anywhere we call `Get-AzAccessToken`.

---

## v2.2.127 — README §4.1 refresh + DCE-creation-via-REST fix + Tag Contributor opt-in (no longer default)

Three changes bundled together — two are fixes the live test surfaced, one is the docs refresh:

### Fix 1 — `New-AzDataCollectionEndpoint` always fails with "InvalidResource" → switch to REST PUT

The Az.Monitor cmdlet `New-AzDataCollectionEndpoint` (verified up to module v0.10.x as of 2026-04) sends a body without the required `properties` wrapper. Live test stack:

```
[STEP] create Data Collection Endpoint
phase=infra FAILED: [InvalidResource] : Invalid resource payload: 'properties' are missing.
```

`Initialize-SIInfra.ps1` now **always uses REST PUT** for DCE creation -- the body is the same shape that was already in the cmdlet-missing fallback path (`{ location, properties: { networkAcls: { publicNetworkAccess: 'Enabled' } } }`), just promoted to the always-on path. The Az PowerShell module is still used to mint the bearer token (`Get-AzAccessToken` inherits the wizard's pre-flighted Az context). The `Az.Monitor` import is now `-ErrorAction SilentlyContinue` and only used for `Get-AzDataCollectionEndpoint` (read-only existence check) when the module ships it. Failure path also now surfaces the actual ARM response body (via `$_.ErrorDetails.Message`) instead of the wrapped exception string, so future ARM errors here get a clear stack.

### Fix 2 — Tag Contributor at tenant-root MG is now opt-in, NOT default

`Tag Contributor` at tenant-root MG lets the SPN write tags to **every resource in every subscription in the tenant** -- way too broad for the default install. It's only needed by the asset-exclusion-tagging engine, which most customers don't run.

`New-SISpn.ps1` now grants:
- **Reader** at tenant-root MG -- always (drives Azure asset-profiling sub discovery + cross-sub LA queries).
- **Tag Contributor** at tenant-root MG -- **only when `-IncludeTagContributor` switch is set**.

`Start-SetupWizard.ps1`'s `/api/apply` handler now passes `-IncludeTagContributor` through when `state.spn.includeTagContributor` is true (a future asset-tagging wizard page will toggle this; for now it stays false → Tag Contributor not granted).

Existing customers who already ran the wizard pre-v2.2.127 will have Tag Contributor at tenant-root MG -- it's harmless on subsequent runs (idempotent re-use sees it as `already in place` and continues). To remove it manually:

```powershell
Remove-AzRoleAssignment -ObjectId <spn-object-id> `
  -RoleDefinitionName 'Tag Contributor' `
  -Scope "/providers/Microsoft.Management/managementGroups/<tenant-id>"
```

### Docs — README §4 fully refreshed

Comprehensive refresh of `README.md` §4 "How to Implement (Quick Start)" to match v2.2.126's wizard reality + add docs the user kept hitting friction on:

**§4.1 — Three-step quick start, fully rewritten:**
- Prereqs section drops the "Global Admin required" hard line (consent-pending fallback handles non-admin operators); lists the actual `Install-Module` commands; calls out the two `Connect-*` commands the operator must run BEFORE launching the wizard.
- Step 2 fully documents the v2.2.113 pre-flight pattern (Connect-AzAccount + Connect-MgGraph in the launching shell; wizard refuses to start if either is missing). Explains why no popups/device-codes inside the wizard process (Conditional-Access-friendly).
- "What the wizard does" 3-row table (SPN / Infrastructure / Config file) with concrete tenant-side outcomes per phase.
- "Engine host + bootstrap auth" 3-row explainer table for Win11/Server vs Azure VM with MI vs Container Apps Job with MI.
- Wizard tour: 9-row screenshot walkthrough table with one PNG per step (Welcome through Setup before/after).

**New sub-section — Permissions granted by the wizard (full disclosure):** 5 tables documenting:
1. 13 Microsoft Graph application permissions granted to the SI SPN.
2. 9 Azure RBAC role assignments — role / scope / why / skip-able.
3. Managed Identity permissions (when host = Azure VM/Container Apps with MI).
4. Entra ID Diagnostic Setting categories (when no-Sentinel path picked).
5. Azure resource provider auto-registrations.

This is the full inventory of what the wizard touches. Nothing hidden.

**New sub-section §4.1.1 — Updating to the latest version:** documents `git pull` workflow (stash → pull → pop), what gets updated vs preserved across pulls (gitignored: custom config + launcher overrides + DATA/OUTPUT + logs + *.bak.*), version verification (`Get-Content .\VERSION`), rollback procedure (`git checkout SI-2.2.<n>`).

**Updated `docs/screenshots/wizard/README.md`** — capture-list now lists 10 screenshot filenames (was 4) covering Welcome + Steps 1-7 + Step 8 before/after with one-line description per screenshot.

---

## v2.2.126 — Setup Wizard: auto-register Azure resource providers + rename "Apply" button to "Setup"

Comprehensive refresh of `README.md` §4 "How to Implement (Quick Start)" to match v2.2.126's wizard reality + add docs the user kept hitting friction on:

**§4.1 — Three-step quick start, fully rewritten:**

- **Prereqs section** rewritten: drops the "Global Admin required" hard line (consent-pending fallback handles non-admin operators), lists the actual `Install-Module` commands, calls out the two `Connect-*` commands the operator must run BEFORE launching the wizard.
- **Step 2 — Authenticate, then launch the Setup Wizard**: fully documents the v2.2.113 pre-flight pattern (Connect-AzAccount + Connect-MgGraph in the launching shell; wizard refuses to start if either is missing). Explains why no popups/device-codes inside the wizard process (Conditional-Access-friendly).
- **What the wizard does** table: 3 rows (SPN / Infrastructure / Config file) with concrete tenant-side outcomes for each phase.
- **Engine host + bootstrap auth** explainer (3-row table for Win11/Server vs Azure VM with MI vs Container Apps Job with MI) covering valid storage options per host.
- **Wizard tour — screenshot walkthrough**: 9-row table with one screenshot per step (Welcome through Setup before/after). Filenames documented in `docs/screenshots/wizard/README.md` so operator knows exactly which PNGs to drop in.

**New sub-section §4.1.0 (in-line) — Permissions granted by the wizard:**

Full disclosure of every grant, in 5 tables:

1. **Microsoft Graph application permissions** (13 perms granted to the SI SPN, with one-line rationale per perm).
2. **Azure RBAC role assignments** (9 rows: role / scope / why / skip-able). Tenant-root MG grants flagged as skip-able via `-SkipTenantRbac`. Workspace + DCR-RG + storage-account scoped grants explained.
3. **Managed Identity** (when host = Azure VM/Container Apps with MI) — the one role the wizard grants to the operator-provided MI (`Key Vault Secrets User` on the cred KV).
4. **Entra ID Diagnostic Setting** (only when no-Sentinel path picked) — the 8 log categories, derived from RA query references.
5. **Azure resource provider registrations** — the 7-8 RPs Phase 2 auto-registers if not already `Registered`.

This is the FULL inventory of what the wizard touches in your tenant. Nothing else gets created or modified.

**New sub-section §4.1.1 — Updating to the latest version:**

Documents `git pull` workflow:
- The `git stash` → `git pull --ff-only origin main` → `git stash pop` dance for preserving local tweaks.
- What gets updated (engines, launchers, queries, docs, wizard).
- What is preserved across pulls (gitignored): `config\SecurityInsight.custom.ps1`, `launcher\<engine>\LauncherConfig.custom.ps1`, `DATA\OUTPUT\`, `logs\`, `*.bak.<timestamp>`.
- Verifying current version after pull (`Get-Content .\VERSION` + `git log -1`).
- Rollback procedure (`git checkout SI-2.2.<n>`).

**Updated `docs/screenshots/wizard/README.md`** — capture-list now lists 10 screenshot filenames (was 4) covering Welcome + Steps 1-7 + Step 8 before/after, with one-line description per screenshot. Operator knows exactly which PNGs to drop in. PowerShell capture commands included.

Ships in lock-step with the wizard backend changes (DCE REST + Tag Contributor opt-in) so customers cloning fresh from `main` see docs that match the wizard they get.

---

## v2.2.125 — Setup Wizard: select-element readability fix (dark navy text, sans font, optgroup styling)

The `<select>` controls (Engine host dropdown on Step 1, Azure region dropdowns on Step 2 + Step 5, model SKU + Shodan tier dropdowns) inherited browser-default text colour -- which renders as a low-contrast light grey on white in several browsers (notably Chrome on Windows). Combined with the `Consolas` monospace font inherited from the input rule, the SELECTED option was hard to read.

**Fix in `styles.css`:**

- Explicit `color: var(--navy)` (`#1a3a5c`) on every input + select + textarea so text is always dark on the light input background.
- Override the input-shared monospace font for `<select>` only -- selects now use the page's primary sans stack (`-apple-system, Segoe UI, Inter, system-ui`) at 14px / weight 500, matching the rail labels and card headings.
- Added explicit colour rules for `<option>` (navy on white) and `<optgroup>` (`#5a6a7a` slate, bold, light-grey background `#f0f4f8`) so the dropdown menu items also read clearly when the dropdown is open.

No HTML / state changes -- pure CSS readability pass.

---

## v2.2.124 — Setup Wizard: fix storage-account empty-name bug + per-step log panel + pre-Apply validation

Three Apply-flow fixes from live test feedback:

**1. Bug: blank storageAccountName became just the suffix.** With v2.2.114's namingSuffix wired through every Step-2 resource and the `storageAccountName` field having no `data-default`, accepting defaults + typing suffix `1` produced `storageAccountName = '1'` (suffix-only). Azure rejected with `[InvalidResource] : Invalid resource payload: 'properties' are missing` mid-Phase 2 -- a misleading Azure error wrapping "name too short".

**Fix:** `nameWithSuffix(key, opts)` now returns empty string instead of fabricating a name from the suffix alone. The Apply payload carries the empty string; the new pre-Apply validator (below) catches it and shows a clear error.

**2. New pre-Apply client-side validator (`validateApplyPayload`).** Runs in `runApply()` *before* the POST hits `/api/apply`. Inspects the built state for blank required fields and surfaces a numbered list:

- Step 1: Tenant ID required.
- Step 2: Subscription ID, region, workspace name + RG, DCE name, storage account + container all required.
- Step 1: Key Vault name required when `Secret + KeyVault` storage selected.

The storage-account problem in particular gets the explicit hint: "the default placeholder 'stmyorgsi' is just a hint -- you must type your actual account name (3-24 chars, lowercase letters + digits, globally unique)". Operator sees the missing field instantly instead of waiting 60 seconds for Azure to reject.

**3. Per-step log panel rendered in the result.** The existing `applyLog` array (built by `Start-SetupWizard.ps1` during apply) now ships in EVERY response (success + failure) -- not just success -- and the JS Apply page renders it as a colour-coded monospace panel below the result banner:

- Green entries: `created`, `granted`, `succeeded`, `ok` matches.
- Red entries: `FAILED`, `ERROR`, `throw` matches.
- Amber entries: `pending`, `consent-pending` matches.
- Grey: everything else.

Backend orchestration enriched to push *granular* sub-step events into `applyLog` -- not just the high-level `phase=spn ok` summaries. New per-step entries:

- **Phase 1 (SPN):** app reg ID + display name; service principal ObjectId; cred kind + storage; cred expiry UTC; per-permission Graph status (one row per perm: `Graph perm granted     : ThreatHunting.Read.All` etc.); per-role-assignment Azure RBAC status.
- **Phase 2 (Infra):** RG name, region, workspace name, DCE name, storage account + container (echoed back so the operator sees what was sent); workspace ResourceId, DCE ResourceId, storage ResourceId (returned by the cmdlet); per-RBAC-grant scope.
- **Phase 3 (Config):** config file path, byte size, list of sections written.

Failure responses also now include `phaseStatus` (the `{spn, infra, config}` map). Previously the failure path didn't ship phaseStatus, so the JS couldn't update the SPN pill from `running` to `ok` when only Phase 2 broke. Result: SPN card stuck on a spinning icon even after SPN finished. Now phaseStatus is in every response and the per-phase pills reflect actual state.

Real **SSE / EventSource log streaming** (live per-step updates while the apply runs, not just buffered at the end) lands in v2.2.125+ -- this tag delivers the buffered version which already cuts the "what just broke" diagnosis time from minutes to seconds.

---

## v2.2.123 — Setup Wizard: deployment name defaults to OpenAI resource INSTANCE name (not the model SKU)

The wizard's two **Deployment name** fields (Step 5 use-existing + create-new branches) defaulted to the model SKU string (`gpt-4.1-mini` / previously `gpt-4o-mini`). That's a wrong convention -- the deployment name is an **arbitrary alias** YOU assign on top of a model, and the recommended pattern (matching real customer configs like Morten's `oai-mortenknudsen-security-insight`) is to align it with the OpenAI **RESOURCE INSTANCE name** so resource + deployment are 1:1.

**Fix:**

- **Use-existing branch deployment field**: default removed (was `gpt-4.1-mini`); placeholder changed to `oai-myorg-securityinsight`. Operator types whatever they actually named their existing deployment in Azure OpenAI Studio > Deployments.
- **Create-new branch deployment field**: default changed from `gpt-4.1-mini` → `oai-myorg-securityinsight` (matches the resource-name default on the same page so the two stay aligned 1:1 by default).
- **Snippet generator**: the createNew snippet's `OpenAI_deployment` line now falls back to the resource name (not the model SKU) when the field is blank, keeping the resource ↔ deployment alignment in the generated config too. The use-existing branch's snippet fallback changed from `gpt-4.1-mini` to a generic `<your-deployment-name>` placeholder.
- **Migration:** `loadState()` now snaps any saved `openAiDeployment` / `openAiNewDeployment` value that's still `gpt-4o-mini` OR `gpt-4.1-mini` (legacy defaults from v2.2.111-v2.2.122) to `oai-myorg-securityinsight` (the new instance-name default). If the operator deliberately wants a model-SKU deployment name they can re-type it after migration.
- **Tooltips rewritten** on both fields to clarify: "deployment name is NOT the model SKU; it's an arbitrary alias YOU created on top of a model. Convention: name it after the resource INSTANCE so they line up 1:1; some teams name it after the SKU -- both work as long as it matches Azure OpenAI Studio > Deployments tab".

The model SKU dropdown (also on Step 5) still defaults to `gpt-4.1-mini` -- that's the actual underlying model and the default is correct.

---

## v2.2.122 — Setup Wizard: auto-migrate stale gpt-4o-mini state to gpt-4.1-mini

v2.2.117 changed the wizard's default OpenAI model SKU + deployment name to `gpt-4.1-mini` (the gpt-4o-mini predecessor was deprecated by OpenAI in 2025). But existing testers' `localStorage` still carried the old `gpt-4o-mini` value -- the data-default seeding only fills when state is null/undefined, so a stale saved value sticks. The dropdown showed the deprecated SKU pre-selected with the "deprecated 2025 -- migrate to gpt-4.1-mini" label.

**Fix:** `loadState()` now auto-snaps three fields whose value `== 'gpt-4o-mini'` to `'gpt-4.1-mini'` on every wizard launch:

- `state.data.openAiModel` (createNew model SKU dropdown)
- `state.data.openAiDeployment` (use-existing deployment name)
- `state.data.openAiNewDeployment` (createNew deployment name)

If the operator deliberately picked `gpt-4o-mini` (e.g. matching an existing deployment with that exact name), the migration overrides their pick on next launch -- by design. If they really need the legacy SKU they can re-pick it from the dropdown's "Legacy (gpt-4o family scheduled for deprecation)" optgroup, and the new value sticks.

---

## v2.2.121 — Setup Wizard: Entra Diagnostic Setting auto-create option (when no Sentinel)

The wizard's Defender XDR linkage card was binary: link an existing Sentinel/XDR workspace, or off entirely. Off-entirely was the wrong default for tenants without Sentinel: RA reports that correlate sign-in risk events with assets had nothing to query against, so they returned empty.

**Fix:** new sub-card on Step 7 -- **"Entra sign-in logs -- auto-stream to SI workspace"** -- visible only when `defenderMode = off` (i.e. when you don't have a Sentinel workspace to link). Off / Enabled toggle. When enabled, the wizard creates an Entra ID Diagnostic Setting on Apply that ships the sign-in + audit log categories straight into your SI Log Analytics workspace.

**Log categories enabled** -- derived from actual SI engine query references (not a guess):

| Category | Purpose | Ref count |
|----------|---------|-----------|
| `SignInLogs` | interactive user sign-ins | 43 |
| `AuditLogs` | directory writes (role assignments, app reg changes) | 5 |
| `NonInteractiveUserSignInLogs` | refresh-token / device-code sign-ins | 3 |
| `ServicePrincipalSignInLogs` | SPN logins (client-credentials grants) | 5 |
| `ManagedIdentitySignInLogs` | MSI logins (Azure-hosted workloads) | 5 |
| `UserRiskEvents` | Identity Protection risk detections | 1 |
| `ProvisioningLogs` | SCIM / cross-tenant provisioning audit | 1 |
| `MicrosoftGraphActivityLogs` | Graph API call audit | 1 |

The list is **derived from grep'ing the engine's RA queries** for table references (`grep -rhoE '\b(SigninLogs|AADNonInteractive...|MicrosoftGraphActivityLogs)\b' engine/`). Future RA queries that reference additional Entra tables will need this list extended.

**State + payload changes:**
- New state key `entraDiagToSI` (`'off'` | `'enabled'`), default `off`. Persisted in localStorage like every other toggle.
- `VIS_FILTERS` extended with `entraDiagToSiBlock`.
- `buildAdvancedSnippet()` writes a new block when enabled: `$global:SI_AutoCreateEntraDiagToSelf = $true` + `SI_EntraDiagSettingName = 'SI-EntraDiag'` + `SI_EntraDiagCategories = @(...)`.
- `buildApplyState()` ships `st.entraDiagnosticSetting = { Enabled, Name, Categories }` to `/api/apply` when enabled. Backend cmdlet (`Initialize-SIInfra.ps1` extension) consumes this in a follow-up tag.

**UI guidance:** the card surfaces two callouts:
- **Teal info box:** the 8 log categories with one-line purpose for each (so the operator sees exactly what the diag setting subscribes to).
- **Amber prerequisite box:** Entra `Security Administrator` or `Global Administrator` role required to create tenant-level Diagnostic Settings; cost note about workspace ingestion (~50-200 MB/day for <500 users); reassurance that the Diagnostic Setting targets only the SI workspace so existing Sentinel sinks stay untouched.

---

## v2.2.120 — Setup Wizard: clarify Defender XDR workspace = Sentinel workspace

The Step 7 "Defender XDR workspace linkage" card and the matching Welcome prereq + tooltip described the workspace abstractly ("the Log Analytics workspace your Defender XDR data is streaming to") -- accurate but unhelpful for operators who think of it as their **Sentinel workspace**. In practice these are the same workspace in 95%+ of tenants (Defender XDR streams into Sentinel via the built-in connector).

**Updated copy in three places:**

- Step 7 card-sub paragraph: "...in most tenants this is your **Microsoft Sentinel workspace** (if you have Sentinel deployed). [...] Off by default; only pick "Linked" if you have a Sentinel / Defender-XDR-streaming workspace."
- Welcome prereq card title: "Defender XDR workspace ResourceId" → "Defender XDR / Sentinel workspace ResourceId". Body now says "in most tenants this is your **Microsoft Sentinel workspace**" + adds the alternative lookup path "Azure portal > your Sentinel workspace > Properties > ResourceId".
- Tooltip on the ResourceId input: same Sentinel-context note + explicit "Leave blank if you don't have Sentinel deployed" guidance for tenants without Sentinel.

No code/state changes -- pure copy clarification so operators recognise the field instantly.

---

## v2.2.119 — Setup Wizard: graceful Ctrl+C handler + branded startup banner + dynamic version

Two listener-process fixes plus a banner refresh:

**1. Ctrl+C now stops the listener cleanly.** `HttpListener.GetContext()` is a synchronous blocking call that runs entirely in the kernel HTTP.sys driver -- pwsh can't interrupt it with Ctrl+C, so the operator was forced to close the pwsh window (or kill the PID from another shell) to stop the listener. Worse: an aborted process leaves an orphaned URL prefix in HTTP.sys that takes minutes to release, so re-launching the wizard on the same port often hits "Access is denied" on `HttpListener.Start()`.

**Fix:** register a `Console.CancelKeyPress` handler that flips a `$script:_stopRequested` flag, calls `$listener.Stop()` (which unblocks the pending `GetContext()` with an `HttpListenerException` our outer try/catch handles), and prints "Ctrl+C received -- stopping listener gracefully...". The `finally` block now also de-registers the handler so subsequent commands in the same pwsh shell respond to Ctrl+C normally, and prints `wizard stopped -- port 8766 released`. Re-launching the wizard works immediately.

**2. Startup banner refreshed + branded.** The previous banner had stale dev breadcrumbs (`v2.2.105: backend cmdlets + /api/apply orchestration LIVE`, `HTML 'Apply' button hookup lands in v2.2.108`) baked in. New banner:

```
===================================================================
 SecurityInsight Setup Wizard
 v2.2.119
===================================================================
 Built by Morten Knudsen, Microsoft MVP
 Web    : https://mortenknudsen.net
 GitHub : https://github.com/KnudsenMorten/SecurityInsight
===================================================================
```

followed by the prereq lines (port, html path, backend cmdlet names) and the green pre-flight `[OK] Az context: ... | Graph context: ...` banners. No more roadmap-tag noise.

**3. Dynamic version everywhere.** The wizard now reads `SOLUTIONS/SecurityInsight/VERSION` at startup into `$siVersion`, displays it in the banner, and serves it via `/api/state.wizardVersion` -- no more hand-edited `'2.2.114'` constant drifting away from reality on every release. If the VERSION file is missing the banner shows `dev`.

---

## v2.2.118 — Setup Wizard: strip developer version-tag notes from the customer-facing GUI

The Welcome page and Step 5 (Azure OpenAI) had several internal version-roadmap notes leaking into the customer-facing UI -- text like "(coming v2.2.112+)", "v2.2.112+ note: the wizard backend will run setup\Validate-SIOpenAI.ps1...", and a "Coming in v2.2.112" amber callout. These are **release-notes content** -- they have no business in the GUI a customer sees on Day 1 of onboarding.

**Cleanup in `Setup-SecurityInsight.html`:**

- "Create new OpenAI resource **(coming v2.2.112+)**" radio label → "Create new OpenAI resource".
- Step 5 createNew sub-form `card-sub` paragraph rewritten: dropped the "v2.2.112+ will run setup\Validate-SIOpenAI.ps1; until then run that script manually" disclaimer. Now reads simply: "Where the new Azure OpenAI resource + deployment land. The wizard provisions a PAYG instance with these names on Apply."
- Step 5 createNew amber-warning callout rewritten + recoloured to teal (`#2a8b9b`): dropped the "v2.2.112+ note" prefix and the script-name reference. Now reads: "On Apply the wizard provisions the OpenAI resource + deployment + key, then writes the endpoint + key into your custom config automatically."

**Cleanup in `app.js` snippet generator:**

- `buildApptagSnippet()` createNew branch: changed `# Resource will be CREATED on Apply by setup\Validate-SIOpenAI.ps1:` → `# Azure OpenAI resource will be CREATED on Apply with these settings:` (script name was an internal implementation detail).
- Subscription fallback `<inherits Step 2 sub>` (which shows up as bracketed text in the snippet) → `(inherits Step 2 subscription)` (parens, full word, less placeholder-looking).
- API key placeholder `'<written-by-apply-backend>'` → `'(filled in by wizard on Apply)'` (clearer + no `<>` placeholder pattern that looks like an unfilled field).
- Endpoint comment `# Endpoint + key written to the lines below by the Apply backend:` → `# Endpoint + API key are filled in by the wizard on Apply:`.

Internal code comments (the `//` lines in `app.js` referencing v2.2.106 / v2.2.111 / v2.2.112 for code-history breadcrumbs) are kept -- those never appear in the GUI and are useful for future maintenance. Same for `app.js` lines 21-22 / 47 / 689 / 889 (PAGES table comments + state defaults + apply page header).

Effect: the wizard now reads as a finished product everywhere the customer looks. Versioning lives in RELEASENOTES.md and git tags, not the GUI.

---

## v2.2.117 — Setup Wizard: refresh OpenAI model SKU dropdown to GPT-4.1 family (gpt-4o-mini deprecated)

The wizard recommended `gpt-4o-mini` as the default OpenAI model SKU + deployment name. That model was deprecated by OpenAI in 2025 in favour of `gpt-4.1-mini` (same price tier, slightly better quality on summarisation). Azure OpenAI customers picking the deprecated SKU on a fresh deployment can still get it for now but will have to migrate within the deprecation window — pointing newcomers at the deprecated SKU is wrong on day one.

**Changes:**

- All `gpt-4o-mini` references in HTML + JS replaced with `gpt-4.1-mini` (deployment name placeholder + data-default; helper text; createNew snippet comment line; copy-snippet output).
- **Model SKU dropdown** on Step 5's createNew sub-form regrouped into 3 optgroups:
  - **GPT-4.1 family (current generation)**: `gpt-4.1-mini` *(recommended)*, `gpt-4.1` *(highest quality)*, `gpt-4.1-nano` *(fastest+cheapest)*.
  - **Reasoning models (overkill for summarisation)**: `o4-mini`, `o3-mini` — listed for operators who already standardise on them.
  - **Legacy (gpt-4o family scheduled for deprecation)**: `gpt-4o`, `gpt-4o-mini` — kept selectable but labelled as deprecated so operators migrating an existing deployment can match what they have.
- Tooltip text: replaced "10x cheaper than gpt-4o" with "10x cheaper than gpt-4.1" (correct family); model SKU tooltip now explicitly mentions "replaces gpt-4o-mini (deprecated 2025)" so operators know why the default changed.
- Region tooltip: updated "gpt-4o-mini is widely available; gpt-4o has tighter region availability" → "gpt-4.1-mini is widely available; gpt-4.1 has tighter region availability".

No behaviour change for existing customers who already typed `gpt-4o-mini` in their custom config — the engine's `OpenAI_deployment` still accepts whatever string Azure returns. This is purely a wizard-default refresh + clearer model picker.

---

## v2.2.116 — Setup Wizard: Welcome prereqs grouped by branch + always-start-on-Welcome

Two related Welcome-page improvements:

**Welcome prereq cards rewritten + grouped by branch.** The previous "Before you begin -- have these handy" list claimed the operator needed *every* item up front -- including a service principal app ID, KV name, secret name, certificate thumbprint, etc. -- regardless of whether they planned to "Use existing" or "Create new" for each. That was wrong: a newcomer picking all the create-new defaults only needs tenant ID + subscription ID + a Global Admin to consent, NOT an existing SPN/KV/cert.

The cards are now in three groups with clear pills/badges:
- **Always required** (4 cards): tenant ID, subscription ID, Azure region, "a user/SPN with the right roles" in the launching shell. Tenant + sub flagged as **Auto-prefilled** by v2.2.115's `/api/state` operatorContext pull.
- **Only if you pick "Use existing" on a step** (4 cards, orange dot): existing SPN App ID (Step 1), existing KV name + secret (Step 1 + KV storage), existing cert thumbprint (Step 1 + cert auth), existing OpenAI endpoint + key (Step 5). Each card explicitly says **Skip if [the create-new alternative is picked]**.
- **Only if you enable optional features** (4 cards, grey dot): SMTP relay, CMDB CSV, Shodan API key, Defender XDR workspace ResourceId. Each card names which step turns it on.

The card title hints which step the value is consumed on (e.g. `(Step 1 -- Use existing SPN + KV storage)`) so newcomers can correlate the prereq with where they'll be asked.

**`init()` now always lands on Welcome on page load.** Bug: the wizard restored `state.currentPage` from localStorage, so reloading the listener (or hitting F5 in the browser) jumped straight to whatever step the operator was on when they last closed the tab -- skipping the Welcome page entirely. That's the WRONG default during active testing, and it was confusing newcomers who hit refresh after reading docs.

**Fix:** `init()` always sets `state.currentPage = 'welcome'` after `loadState()`. localStorage answers are still preserved -- every previously-typed value is back in the inputs when the operator clicks Next or jumps via the rail. Only the *current page pointer* is reset.

---

## v2.2.115 — Setup Wizard: auto-prefill tenantId + subscriptionId from operator's connected context

The wizard required the operator to manually type tenant ID + subscription ID even though they had **just authenticated** to those exact values via `Connect-AzAccount` + `Connect-MgGraph` in the launching shell. Pure friction -- and if they typed wrong, the snippet showed `$global:SpnTenantId = '<tenant-guid>'` (placeholder) until the field was filled, which was confusing.

**Fix:**

- `Start-SetupWizard.ps1` -- `/api/state` response now carries an `operatorContext` object: `{ tenantId, subscriptionId, subscriptionName, azAccount, mgAccount, mgScopes }`. Pre-flight already required both contexts to be loaded, so these are guaranteed present. SubscriptionName is included so the wizard UI can render `"Acme PAYG (85846a15-...)"` instead of just the GUID.
- `app.js` -- new `autoFillFromOperatorContext()` async function called on init. Fetches `/api/state`, and if `state.data.tenantId` / `state.data.subscriptionId` are blank, fills them from `operatorContext` and saves to localStorage. Best-effort: if the wizard is opened from `file://` (no listener), the fetch fails silently and the operator types as before.
- Only fills **blank** state -- never overrides what the operator typed. Re-opening the wizard after typing a different tenant ID won't snap back.

**Result:** open the wizard → Step 1 + Step 2 already have your tenant + sub pre-filled → snippet preview shows the real GUIDs from the start, no `<tenant-guid>` placeholder anywhere.

---

## v2.2.114 — Setup Wizard: namingSuffix wired through snippet + Apply payload

The `namingSuffix` field on Step 2 (added in v2.2.112) was state-bound to `localStorage` but **not actually applied** to the snippet preview or the `/api/apply` payload. So picking suffix "1" had no visible effect — operators got the bare default names in both the preview and the provisioned resources.

**Fix.** Two new helpers:

- `nameWithSuffix(key, opts)` — reads `state.data[key]` (falls back to the input's `data-default` if empty), appends `state.data.namingSuffix` with the right separator. `opts.storage = true` for storage account names: strips non-alphanumerics from the suffix (storage account names can't have hyphens), lowercases, and truncates to Azure's 24-char limit.
- `suffixedAssignLine(varName, key, fallback, pad, opts)` — same shape as `assignLine` but uses `nameWithSuffix`. Adds a `# default+suffix` tag in the snippet when a suffix is in effect (vs `# default` for plain defaults).

**`buildWorkspaceSnippet`** now suffixes the seven Step-2 resources whenever a suffix is set: `SI_WorkspaceName`, `SI_WorkspaceResourceGroup`, `SI_DceName`, `SI_DceResourceGroup`, `SI_DcrResourceGroup`, `SI_StorageAccount` (with `{storage:true}`), `SI_StorageResourceGroup`, `SI_ExportContainer`. A header comment at the top of the block flags the suffix in effect: `# Naming suffix in effect: "-1" (applied to all default names below)`.

**`buildApplyState`** uses the same `nameWithSuffix()` for `infra.resourceGroupName / workspaceName / dceName / dceResourceGroup / storageAccountName / storageResourceGroup / storageContainer` so the names sent to `/api/apply` match what the operator sees in the snippet preview. Also passes `namingSuffix` through as a top-level field (for backend logging and audit).

**Examples** with suffix `1`:
- `log-platform-management-securityinsight` → `log-platform-management-securityinsight-1`
- `rg-securityinsight` → `rg-securityinsight-1`
- `dce-securityinsight` → `dce-securityinsight-1`
- `stmyorgsi` → `stmyorgsi1` *(storage account: hyphen stripped, no separator)*
- `securityinsight` *(container)* → `securityinsight-1`

**Examples** with suffix `-preview`:
- `log-platform-management-securityinsight` → `log-platform-management-securityinsight--preview` *(double-hyphen — leading hyphen in the suffix is intentional from the operator)*

If the suffix is left blank, behaviour is identical to v2.2.113 (no suffixing).

User-overridden names are still suffixed -- if you typed `my-special-workspace` and set suffix `1`, the snippet shows `my-special-workspace-1`. If that's not desired, leave the suffix blank and add it manually to your custom names.

---

## v2.2.113 — Setup Wizard: graceful admin-consent + pre-flight perms probe + region dropdown + AOAI create-new fields

This is the last big "make the wizard production-ready" tag before live-customer testing. Six related changes:

### 1. Graceful admin-consent flow (no more silent failures)

The #1 customer-onboarding stall is **admin consent on Microsoft Graph permissions**. The operator running the wizard often doesn't have **Privileged Role Administrator** or **Global Administrator** -- they're a tenant user with rights to *create* the SPN but not to consent to its app-only Graph permissions. The previous backend swallowed those grant failures into log warnings, returned a `success` result, and the operator had no idea downstream engines would fail with `Insufficient privileges` because half the perms were never consented.

**`New-SISpn.ps1`:**
- **Per-permission status tracking.** Each Graph permission carries one of `granted` / `already` / `pending` / `not-found` / `skipped`. Returned in result as `GraphPermissionResults` (array of `{Name, Status, Error}`).
- **Aggregate `ConsentStatus`**: `granted` (all OK), `partial` (some failed), `pending` (none granted), `failed`.
- **`PendingPermissions`** result field for easy display.
- **`ConsentUrl`** computed and returned: `https://login.microsoftonline.com/{TenantId}/adminconsent?client_id={AppId}` -- a Global Admin clicks once, all pending perms get consented in a single Entra portal flow.
- **Same per-result tracking for Azure RBAC grants** (`AzureRbacResults` array with `{Name, Scope, Status, Error}`).
- **New `-SkipTenantRbac` switch.** Skips the Reader + Tag Contributor grants at tenant-root MG. Useful for sandbox tests + orgs that won't authorize tenant-root assignments.

**`/api/apply` orchestration (`Start-SetupWizard.ps1`):**
- New SPN-phase status: **`consent-pending`** in `phaseStatus.spn` when SPN created but consent partial.
- Apply does **NOT fail** on consent-pending -- continues with infra + config phases. Custom config gets written so engines run as soon as a Global Admin consents (no re-apply needed).
- New optional state fields: `st.spn.skipTenantRbac` and `st.spn.skipAdminConsent`.

**Wizard Apply page UI (`app.js`):**
- New phase-pill status `consent-pending` (amber warning triangle ⚠).
- Top-of-page state pill flips from `DONE` to **`CONSENT PENDING`** with amber background.
- Result panel surfaces a yellow callout listing pending permission names + a big **"Open admin-consent page"** button linking the consent URL + two-step instruction (hand URL to Global Admin, then re-click Apply to verify -- Apply is idempotent).

### 2. Fail-fast on missing Az + Microsoft Graph contexts

Previous behaviour: `New-SISpn.ps1` and `Initialize-SIInfra.ps1` had internal `Connect-AzAccount` and `Connect-MgGraph` fallback calls. In the listener (which runs in a hidden background process), these triggered interactive auth dialogs that were invisible -- the cmdlet hung forever and the operator saw "no resources in RG" with no error to debug.

Plus device-code auth is **blocked by Conditional Access in many tenants** (and is itself a CA security-risk pattern -- not acceptable as a fallback).

**Fix:**
- `Start-SetupWizard.ps1` startup runs `Test-PreflightAuth` -- requires both `Get-AzContext` and `Get-MgContext` to be loaded **before** the listener starts. If either is missing, the wizard refuses to start with a clear error showing exactly what `Connect-*` commands the operator needs to run in the launching shell.
- `New-SISpn.ps1` similarly checks both contexts at function entry; if missing, throws with the same instruction. **No internal `Connect-*` calls anywhere in the wizard backend.**
- The operator authenticates how their CA policy allows (browser-redirect, cert-based SPN, whatever), in their own shell. The wizard process inherits both contexts -- one auth, no popups, no per-call re-auth.

### 3. Pre-flight permission probe + new `/api/preflight` endpoint

Authentication-presence isn't enough -- the operator might be authed but lack the *roles* to actually do things. New `Test-PreflightPermissions` function checks:
- **Microsoft Graph scopes**: required `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `Directory.ReadWrite.All` are present on the active Mg context.
- **Entra directory roles** (best-effort, when operator is a user not an SPN): looks up the operator's directory role memberships and warns if no admin-consent role (`Global Administrator`, `Privileged Role Administrator`, `Cloud Application Administrator`, `Application Administrator`) is held -- "expect Graph grants to land 'pending'; need a separate admin to click consent URL".
- **Azure RBAC at the target subscription**: blocker if no `Owner` / `Contributor` / `User Access Administrator`; warning if Contributor only (some RBAC grants in Initialize-SIInfra need Owner/UAA).

Exposed via `POST /api/preflight` with `{tenantId, subscriptionId}` body -- returns `{blockers, warnings, roles, ready}`. The wizard JS Apply page (and any external automation) can call this **before** clicking the real Apply, so the operator sees missing roles BEFORE any provisioning starts.

Handles SPN-vs-user auth correctly: detects GUID-shaped Account.Id and uses `Get-AzADServicePrincipal` + `-ObjectId` instead of `-SignInName` (which only works for user UPNs).

### 4. Microsoft Graph scope list trimmed (AADSTS650053 fix)

Removed `DelegatedPermissionGrant.ReadWrite.All` from the wizard's required Graph scopes. That scope is for *delegated* (user-impersonation) permission grants -- the wizard only does *application-only* grants which `AppRoleAssignment.ReadWrite.All` covers. Asking for it triggered `AADSTS650053: scope ... doesn't exist on the resource` in some tenants when the Graph SDK truncated the scope on `Connect-MgGraph`. Both `New-SISpn.ps1` and the wizard pre-flight now request 3 scopes instead of 4.

### 5. Step 2 — full Azure region dropdown (no silent fallback)

Step 2 (Workspace + ingestion) didn't collect `location` -- `buildApplyState()` hardcoded `'westeurope'` as a fallback. Customers in other regions had to manually edit the generated config or pre-set state via `localStorage`.

**Fix:** new **Azure region** dropdown next to Subscription ID with **53 regions** organised into 7 geographic optgroups (Europe, North America, South America, Asia Pacific, Australia + NZ, Middle East, Africa). Each region shows the city name in parentheses. Default = West Europe; required field; Step 2 done-badge + Next button gate on it.

`buildWorkspaceSnippet()` and `buildApplyState()` now read `state.data.location` -- no more silent fallback.

### 6. Step 5 — OpenAI "Create new resource" sub-form

The Create-new branch on Step 5 (Azure OpenAI) was a placeholder note. It now collects everything needed to provision the resource on Apply (when the v2.2.114+ backend creates it via `setup\Validate-SIOpenAI.ps1`):
- **OpenAI resource name** (default `oai-myorg-securityinsight`)
- **Resource group** (default `rg-securityinsight-openai` -- separate from the SI workspace RG so cost tags / policies can differ)
- **Subscription** (optional -- inherits Step 2 sub if blank)
- **Azure region** dropdown with **two optgroups**: "Best gpt-4o-mini availability" (8 regions) + "Other AOAI-enabled regions" (11 more) -- AOAI region availability is more constrained than general Azure
- **Deployment name** (default `gpt-4o-mini`)
- **Model SKU** dropdown: `gpt-4o-mini` (recommended) / `gpt-4o` (highest quality) / `gpt-4-turbo` (legacy) / `gpt-35-turbo` (cheapest)

**Snippet upgrade:** `buildApptagSnippet()` now writes the AI consumer globals (`$global:BuildSummaryByAI = $true`, `OpenAI_endpoint`, `OpenAI_deployment`, `OpenAI_apiVersion`, `OpenAI_apiKey`) for **both** modes. Create-new path computes the endpoint URL from the resource name (`https://{name}.openai.azure.com/`) and marks the API key as `<written-by-apply-backend>` so the operator knows the backend will fill it on Apply -- no manual config edit needed.

**Bonus on the same step:** `MaxAiSpendPerRun` now defaults to **3 USD** (pre-filled, not just placeholder) matching the real customer config pattern. Tooltip rewritten to clarify the engine *continues* on budget cap (sets `SI_Classify_Status='budget-capped'` per asset, doesn't throw).

### Other polish

- Step 1 title rewritten from "Who are we authenticating as?" → "**How will the SecurityInsight engines authenticate?**" (more professional / matches the wizard's other titles).
- Validators added for the 5 new openAI createNew fields + the new `location` field.
- Listener startup now prints which contexts are inherited (green `[OK]` lines for Az + Graph) so the operator confirms before clicking Apply.

### What's NOT yet done

- **Backend create-AOAI** (`Validate-SIOpenAI.ps1` integration on Apply) -- v2.2.114.
- **Backend create-KV** (createNewKv flag from v2.2.110 honored by `Initialize-SIInfra.ps1`) -- v2.2.114.
- **Use existing resource by ResourceId** pattern (single-field paste vs name + RG + sub) -- v2.2.115.
- **Live tenant validation** of the full Apply flow -- the only uncovered piece. The auth pre-flight, consent-grace, and per-phase logging are all on disk + parse-clean; full E2E test pending operator with both contexts loaded.

---

## v2.2.112 — Setup Wizard: storage account fields on Step 2 (workspace + ingestion)

The wizard's Step 2 collected workspace + DCE but never asked for the **storage account** -- the third leg of the SI ingestion stool (fingerprint cache + worker queue + Excel staging container). The backend `Initialize-SIInfra.ps1` already accepted `storageAccountName` / `storageResourceGroup` / `storageContainer` parameters but the HTML never sent them. Without the storage account, the engine prestage fell back to "compute from workspace name" which clashed for customers running prod + preview side-by-side, or for any name that didn't satisfy Azure's strict storage-account naming rules (3-24 chars, lowercase letters + digits only, globally unique).

**New fields on Step 2 (Storage account card):**

- `storageAccountName` — 3-24 chars, lowercase a-z and 0-9, globally unique. Inline validator enforces the regex; tooltip explains the convention `st<org>si` / `st<org>securityinsight`. Engine creates the account on first prestage if missing and grants the SPN **Storage Blob/Table/Queue Data Contributor** on the account scope.
- `storageResourceGroup` — defaults to the workspace RG (`rg-securityinsight`), keeping the SI footprint in one RG. Tooltip explains the trade-off.
- `storageContainer` — blob container that holds staged Excel reports + the fingerprint cache. Defaults to `securityinsight`. Inline validator enforces Azure container naming (3-63 chars, lowercase + digits + hyphens).
- `namingSuffix` — *optional* — a free-form suffix string (e.g. `-v22`, `-preview`, `-prod`). Documented in the tooltip; not yet auto-applied to the other Step-2 defaults but state-bound for v2.2.113 to consume.

**Snippet upgrade.** `buildWorkspaceSnippet()` now emits the v2.2-correct `$global:SI_*` block (matching the shape of customer custom files): `SI_PrestageInfra=$true`, `SI_AzSubscriptionId`, `SI_Location`, `SI_WorkspaceName`, `SI_WorkspaceResourceGroup`, computed `SI_WorkspaceResourceId`, `SI_DceName`, `SI_DceResourceGroup`, `SI_DcrResourceGroup` (defaults to DCE RG), `SI_StorageAccount`, `SI_StorageResourceGroup`, `SI_ExportContainer`, computed `ExportDestination`. Replaces the legacy `SubscriptionId` / `WorkspaceName` / `WorkspaceResourceGroup` shortform that didn't include the `SI_` prefix.

**Page completion gate.** `PAGE_REQS.workspace` now requires the storage trio (`storageAccountName`, `storageResourceGroup`, `storageContainer`) in addition to the workspace + DCE fields. Step 2's "done" badge in the rail and the Next button both honor the new check.

**Apply payload upgrade.** `buildApplyState()`'s `infra` object now passes `dceResourceGroup`, `storageResourceGroup`, `storageContainer` through to `/api/apply` so the backend `Initialize-SIInfra.ps1` provisions everything in one call (workspace + RG + DCE + DCE RG + storage account + storage RG + container + RBAC).

**Tooltips on every field.** Step 2's existing fields (DCE name + RG) gained `?` tooltips matching the v2.2.111 pattern; the new storage trio + naming suffix all carry tooltips with concrete naming examples and what-if-blank guidance.

**Coming next (v2.2.113+):**
- Per-mode mail recipients on Step 3 (`RiskAnalysis_Summary_To`, `RiskAnalysis_Detailed_To`).
- Auto-apply `namingSuffix` to the workspace / RG / DCE / storage defaults so a single suffix word produces a consistent prod-vs-preview deployment.
- "Use existing resource by ResourceId" pattern for KV / Storage / OpenAI / Log Analytics workspace.
- Activate `raexcl` + `assettag` power-user pages.

---

## v2.2.111 — Setup Wizard: full optional-section pages live with mouseover help + requirements-aware sub-fields

The wizard is no longer 3 functional pages plus 7 placeholders — it's now 8 functional pages end-to-end. Steps 3-7 (previously "Coming soon" cards) are activated and rewritten with master-toggle / sub-block UX so customers only see fields that apply to the choice they made.

**New active pages (each opt-in: master toggle defaults OFF):**

- **Step 3 — Mail / SMTP.** Off (no mail) / Anonymous relay / Authenticated. When *Anonymous*: Server, Port, UseSSL, From, MailTo. When *Authenticated*: adds User + Password fields below in a separate sub-card. *Off* hides everything below the toggle.
- **Step 4 — CMDB integration.** Off / CSV file. CSV path + refresh-interval-hours when on.
- **Step 5 — Azure OpenAI.** Off / Enabled. When *Enabled*: a sub-toggle picks **Use existing OpenAI resource** (paste endpoint + deployment + key + version + max-spend) or **Create new** (placeholder for v2.2.112+ — wizard will run `Validate-SIOpenAI.ps1` automatically on Apply). Defaults to existing-resource path.
- **Step 6 — Shodan attack surface.** Off / Enabled. When *Enabled*: API key + a **license-tier dropdown** (Free / Membership / Small Business / Corporate) that drives the engine's per-run rate-limit budget so it backs off before Shodan starts rejecting calls.
- **Step 7 — Output sinks + Defender XDR.** Two independent toggles: a checkbox for **JSON sink** (adds `'JSON'` to every `SI_Sinks_<Engine>`) and an Off/Linked toggle for **Defender XDR workspace ResourceId** (used by RA cross-correlation reports).

**New tooltip system.** Every input that needs a "what does this mean / where do I find it" hint carries a `?` icon next to its label. Hovering or focusing the icon shows a 320px-wide dark popup with plain-English help — where in the Azure portal to find the value, what format it expects, what the recommended default is, and what happens if you skip it. Pure CSS (`.help::after { content: attr(data-tip) }`), no JavaScript hover handlers, no external library.

**Master-toggle / sub-block visibility.** The existing `syncCredBlocks()` framework (compound visibility filters) was already designed for this — v2.2.111 just adds five new filter keys to the `VIS_FILTERS` map (`smtpModeBlock`, `cmdbModeBlock`, `openAiModeBlock`, `openAiResModeBlock`, `shodanModeBlock`, `defenderModeBlock`). Each sub-block carries `data-<x>-mode-block="anon,auth"` (multi-value supported since v2.2.110) and is hidden when the master toggle says "off".

**`hydrateForms()` now handles `<input type="checkbox">` separately** from text inputs. The previous code path read `input.value.trim()` on checkboxes, which gave `'on'` or `''` instead of a boolean — fine for the Apply payload (`d.smtpUseSsl !== false` worked) but flat-out wrong for `enableJsonSink`. Checkboxes now bind to `state.data[key] = !!cb.checked`.

**Snippet generators** added for all five new pages (`buildOutputSnippet`, `buildCmdbSnippet`, `buildApptagSnippet`, `buildShodanSnippet`, `buildAdvancedSnippet`). Each returns either an "OFF -- nothing written" placeholder when the master toggle is off, or the matching `$global:*` PowerShell block targeted at `config/SecurityInsight.custom.ps1` (Layer 3). Snippets re-render live as the operator types.

**`buildApplyState()` rewired** to read the new master toggles instead of guessing from raw field presence:
- `if (d.smtpMode && d.smtpMode !== 'off')` → `st.smtp = { Mode, Server, Port, UseSsl, From, MailTo }` plus `User`/`Password` only when `Mode === 'auth'`.
- `if (d.openAiMode === 'enabled' && d.openAiEndpoint)` → `st.openAi = { Endpoint, Deployment, ApiKey, ApiVersion, MaxSpendPerRun }`.
- `if (d.shodanMode === 'enabled' && d.shodanApiKey)` → `st.shodan = { ApiKey, LicenseTier }`.
- `if (d.cmdbMode === 'csv')` → `st.cmdb = { Enabled, RefreshHours, CsvPath }`.
- `if (d.defenderMode === 'linked' && d.defenderWorkspaceResourceId)` → `st.defenderWorkspaceResourceId`.

**Step count updated to "8 of 8"** in every page eyebrow and the welcome hero. Two pages stay deactivated as power-user features for v2.2.112+: `raexcl` (per-report CVE/config exclusions) and `assettag` (manual tier overrides).

**Coming next (v2.2.112+):**
- Backend `Validate-SIOpenAI.ps1` integration so "Create new OpenAI resource" actually creates one on Apply.
- "Use existing resource by ResourceId" pattern for KV / Storage / OpenAI / Log Analytics workspace (single-field paste vs name + RG + sub).
- Activate `raexcl` + `assettag` power-user pages.
- Backend `New-AzKeyVault` for the createNewKv path.

For testers: clear localStorage (DevTools → Application → Local Storage → Clear) or open a private window to verify the new pages render from a clean slate.

---

## v2.2.110 — Setup Wizard: ask "host + bootstrap auth" first, gate every storage option below

The Credential card had a long-standing chicken-and-egg problem: it offered **Client secret + Azure Key Vault** as a valid combo for any host. But on a Win11 / Win Server box without a Managed Identity, there's nothing the engine can use to *read* the secret from KV at startup — KV access itself needs an authenticated identity, and the secret we want to retrieve IS that identity. Same problem for **Self-signed cert + Local cert store** in an Azure Container Apps Job — there's no traditional Windows cert store inside an ephemeral container.

**New first card on Step 1: "Engine host + bootstrap auth"** (a 3-option `<select>` dropdown):

| Host | Bootstrap auth | Valid SI cred storage |
|------|----------------|------------------------|
| **Windows 11 / Windows Server** (on-prem, or Azure VM *without* MI) — *default* | None — must work without prior Azure auth | **Cert + Local cert store** *(production)* &nbsp; OR &nbsp; **Secret + Inline** *(testing only)* |
| **Azure VM** *with* system-assigned Managed Identity | The MI on the VM | Cert / Secret in Key Vault, Cert in local cert store, Secret inline (any combo) |
| **Azure Container Apps Job** *with* system-assigned Managed Identity | The MI on the job | Cert / Secret in Key Vault, Secret inline (no local cert store — ephemeral container) |

Each host choice gets a coloured callout below the dropdown explaining the bootstrap chain in plain English (orange-amber for the Win path; green for the two MI paths). The wizard makes the trade-off explicit so newcomers don't pick a combo that can't bootstrap.

**The storage radios on the Credential card auto-filter** based on the host pick:

- `data-host-type-block="azureVMMI,azureContainerMI"` on the **Azure Key Vault** label → hidden on Win.
- `data-host-type-block="win,azureVMMI"` on the **Local cert store** label → hidden on Container.
- **Inline in custom.ps1** stays available everywhere but now also carries a red `(testing only)` marker — secret in plaintext on disk is fine for dev/lab, not for production.

**Auto-snap when a pick becomes invalid:** `syncCredBlocks()` now calls `snapCredStorage()` which checks the current `(hostType, credType, credStorage)` triple against a whitelist (`VALID_STORAGE_BY_HOST` × `VALID_STORAGE_BY_CRED`) and silently moves `state.data.credStorage` to the first valid option for the new combo. Examples:

- Was on **Azure VM MI + Cert + KeyVault** → flip host to **Win** → KeyVault becomes invalid → snap to **LocalCertStore**.
- Was on **Win + Secret + Inline** → flip cred type to **Cert** → Inline becomes invalid for cert → snap to **LocalCertStore**.

**`syncCredBlocks()` refactored to a generic single-pass.** Old version had three separate iterations with overlapping logic. New version reads a `VIS_FILTERS` map (`{ spnModeBlock: 'spnMode', credBlock: 'credType', credStorageBlock: 'credStorage', hostTypeBlock: 'hostType' }`) and applies compound visibility uniformly. Filter values support comma-separated whitelists (`data-host-type-block="azureVMMI,azureContainerMI"`) so an option valid for *multiple* host types can declare them in one attribute instead of needing inverse logic.

**`hydrateForms()` now wires `<select data-key="...">` elements** the same way as text inputs — first-touch default seeding (from `data-default`), state binding on `change`, and `syncCredBlocks()` re-run after every change. Without this, the new host dropdown wouldn't have persisted to `localStorage`.

**`buildApplyState()` passes `hostType` through** to `/api/apply` (top-level `st.hostType`) so the backend can record which host profile the operator picked when it writes the config file. Backend cmdlets (`New-SISpn.ps1`, `Initialize-SIInfra.ps1`, `Write-SICustomConfig.ps1`) accept the new field but don't yet branch on it — the v2.2 engine reads `$global:SI_HostMode` from `LauncherConfig.custom.ps1` (preview.18 contract) and that hook is unchanged. Wizard-set `hostType` will start affecting backend behaviour in `v2.2.111+` (createNew vs use-existing KV, cert-store path selection, container-mode launcher template choice).

**Clear localStorage if testing** — old wizard sessions don't have `state.data.hostType`; the defensive default (`'win'`) kicks in on next page load, but the storage radios may render once with the old combo before the auto-snap settles.

---

## v2.2.109 — Setup Wizard: fix Credential card visibility (secret vs cert combinations)

The Credential card on Step 1 was showing impossible combinations: with **Client secret** picked, the wizard still rendered the Use-existing **Key Vault name + Secret name** input pair, the Use-existing **Certificate thumbprint** input, AND the **Local cert store (cert only)** storage radio. Three distinct bugs:

**Bug 1 — `.form-grid` overrode `[hidden]`.** The two Use-existing input blocks (`data-spn-mode-block="useExisting"`) carry the `form-grid` class. The CSS rule `.form-grid { display: grid }` and the user-agent rule `[hidden] { display: none }` have equal specificity (0,1,0), and the site rule lands later — so it wins. `b.hidden = true` from `syncCredBlocks()` was silently ineffective on those blocks; they kept showing in Create-new mode regardless of toggle state. **Fix:** `[hidden] { display: none !important; }` added at the top of the form section in `styles.css` so the HTML attribute behaves consistently across every element class in the wizard.

**Bug 2 — cred-storage radios had no cred-type filter.** The "Local cert store" and "Inline in custom.ps1" labels self-document as `(cert only)` and `(secret only)` but the wizard let either be selected regardless of `credType`. **Fix:** added `data-cred-block="certThumb"` to the LocalCertStore label and `data-cred-block="kvSecret"` to the Inline label, so the existing `syncCredBlocks()` cred-only branch hides each label when its credential type isn't selected. KeyVault stays visible for both (it works for secret AND cert).

**Bug 3 — illegal `credType x credStorage` could survive a cred-type flip.** If the user picked **Self-signed certificate** + **Local cert store**, then flipped to **Client secret**, the LocalCertStore radio would correctly hide (post bug-2 fix) — but `state.data.credStorage` would still equal `'LocalCertStore'`, so the snippet preview / Apply payload would carry an invalid combo. **Fix:** `syncCredBlocks()` now auto-snaps `credStorage = 'KeyVault'` when the current pick becomes invalid for the new cred type (`secret + LocalCertStore` → `KeyVault`; `cert + Inline` → `KeyVault`). KeyVault is always-valid so the snap is silent and reasonable.

**Bonus defensive fix:** `syncCredBlocks()` now seeds `spnMode='createNew'`, `credType='kvSecret'`, `credStorage='KeyVault'` defaults at function entry, so any pre-v2.2.106 localStorage state that's missing those three keys can't trip the visibility pass into showing every block at once.

**Bonus default seeding:** the **Key Vault name** input on the Create-new + KeyVault path now also pre-fills with `kv-securityinsight` (matches the `kv-securityinsight` placeholder), so newcomers can click Next without typing — same pattern as the other 6 default-seeded inputs from `v2.2.107`.

For testers: clear localStorage (DevTools → Application → Local Storage → Clear) or open a private window to verify the fix from a clean slate. Existing test sessions will pick up the auto-snap correction on the next click.

---

## v2.2.108 — Drop CUSTOMDATA from new SI deployments (everything lives under config\)

The legacy `CUSTOMDATA\` folder name is gone from every code path the SecurityInsight bootstrap touches. Files that used to live in `SOLUTIONS\PlatformConfiguration\CUSTOMDATA\` now live in `SOLUTIONS\PlatformConfiguration\config\` (same gitignore rules apply: `.sample.*` files are tracked, real `*.ps1` instances are customer-owned and gitignored). New deployments will no longer scaffold a `CUSTOMDATA\` folder anywhere under the install root.

**What changed:**

- `FUNCTIONS\AutomateITPS\Public\Initialize-PlatformDefaults.ps1` — Layer-1 platform-defaults loader now resolves `SOLUTIONS\PlatformConfiguration\config\platform-defaults.ps1` first. If the new path isn't populated yet but a legacy `CUSTOMDATA\platform-defaults.ps1` is present (existing customer machines that haven't migrated), the function transparently reads the legacy file and emits a verbose hint to move it. Zero forced-migration friction — old hosts keep working, new hosts get the new layout.
- `FUNCTIONS\AutomateITPS\Public\Initialize-PlatformAutomationFramework.ps1` — step 6b's docstring updated to reflect the new path; back-compat note added.
- `SOLUTIONS\PlatformConfiguration\CUSTOMDATA\platform-defaults.sample.ps1` → `SOLUTIONS\PlatformConfiguration\config\platform-defaults.sample.ps1` (file moved; the in-file `TO UPDATE: notepad ...\CUSTOMDATA\...` hint repointed to `...\config\...`).
- `SOLUTIONS\SecurityInsight\Setup-SecurityInsight.ps1` — `$customDataDir` / `$customDataPath` PowerShell variables renamed to `$configDir` / `$configPath`. The actual paths were already `config\` — only the misleading variable names were leftover from an earlier rename pass.
- `SOLUTIONS\SecurityInsight\tests\Test-Smoke.ps1` — same rename of the `$customDataPath` local variable.
- `SOLUTIONS\SecurityInsight\demo\community\config\SecurityInsight.custom.ps1` — docstring comment updated from `.gitignore:66 -- SOLUTIONS/*/CUSTOMDATA/*` to point at the current `config/` rule.

**What didn't change:**

- The `.gitignore` keeps both `SOLUTIONS/**/config/*` and `SOLUTIONS/**/CUSTOMDATA/*` rules (belt + suspenders for the 8 other solutions in the AutomateIT monorepo that still have `CUSTOMDATA\` folders with real customer data — those solutions migrate on their own cadence).
- The publish workflow's `CUSTOMSCRIPTS|CUSTOMDATA` regex guards stay in place — they protect against accidentally shipping customer files to public repos and that protection is independent of the rename.
- v2.1 historical notes in this file (the 2.2.0 cleanup that originally removed the SI-side `CUSTOMDATA/`) are preserved verbatim.

**For customers running an older install:** you don't need to do anything. Engines keep finding `platform-defaults.ps1` in either location. When you have time, move:

```powershell
Move-Item C:\AutomateIT\SOLUTIONS\PlatformConfiguration\CUSTOMDATA\platform-defaults.ps1 `
          C:\AutomateIT\SOLUTIONS\PlatformConfiguration\config\platform-defaults.ps1
Remove-Item C:\AutomateIT\SOLUTIONS\PlatformConfiguration\CUSTOMDATA -Force -ErrorAction SilentlyContinue
```

---

## v2.2.107 — Setup Wizard: Apply page (POST → 3-phase progress UI) + default-seeded inputs

The HTML wizard's final step (Step 10) is no longer a "copy this snippet" placeholder — it now drives the v2.2.105 `/api/apply` backend end-to-end from the browser. Click **Apply now**, and the wizard creates the SPN, provisions Log Analytics + DCE + Storage (RBAC-only), and writes `config\SecurityInsight.custom.ps1` for you. No copy/paste, no PowerShell.

**Apply page (Step 10) — what it shows:**

- **Three summary cards** before you click — exactly what the wizard will do for *(1) SPN*, *(2) Infrastructure*, *(3) Config file* — built from your answers across all earlier steps.
- **Big "Apply now" button** + **state pill** (`READY` → `RUNNING` → `DONE` / `FAILED`).
- **Per-phase progress UI** (`SPN` / `Infrastructure` / `Config file`): each phase has its own card with a pending / running / ok / failed icon and status. The running phase gets an animated spinner.
- **Result panel** on success: SPN AppId, Workspace resource ID, config-file path + bytes + sections written.
- **Result panel** on failure: which phase broke, the error message, and which phases the backend reports as `ok` / `pending` / `failed` so you know what to re-run.
- **Secret-redacted state JSON preview** below the action — so power users can see the exact payload being POSTed (SMTP / OpenAI / Shodan API keys all rendered as `***`).

**First-touch default seeding** — recommended values are now pre-filled into the input fields, not just shown as ghost placeholder text. Six fields seed automatically on first load:

- `spnDisplayName` → `sp-securityinsight`
- `secretName` (Use-existing mode) → `SecurityInsight-Secret`
- `workspaceName` → `log-platform-management-securityinsight`
- `workspaceRg` → `rg-securityinsight`
- `dceName` → `dce-securityinsight`
- `dceRg` → `rg-dce-securityinsight`

Newcomers who want the v2.2 standard layout can now click straight through Next → Next → Apply without typing a single value (besides the GUIDs that have to come from your own tenant). Power users see the same defaults and overwrite them inline; the snippet preview keeps a `# default` tag next to any line whose value still matches the recommended setting.

**Cosmetic:** Step 1's SPN-mode toggle now reads **"Create new SecurityInsight Service Principal"** / **"Use existing Service Principal"** instead of the older "Create new SPN (recommended for newbies)" — clearer about what the wizard will name the app registration.

**End-to-end story for a new customer is now complete:**

1. Open `Start-SetupWizard.ps1` → browser at `http://localhost:8766`.
2. Step 1 — Tenant ID + accept the SPN display-name default.
3. Steps 2-9 — accept defaults or override.
4. Step 10 — review summary, click **Apply now**, watch the three phases turn green.
5. `config\SecurityInsight.custom.ps1` is on disk; the engine is ready to run.

**What's still pending:**
- Live log SSE streaming on `/api/log-stream` so the Apply page tails per-phase stdout in real time — `v2.2.108`.
- Drop Power BI + Workbook tabs from the HTML wizard — `v2.2.108`.
- Smoke-test on lab + 2 customer tenants, README Step 2 rewrite to "fully working" status — `v2.2.109`.

---

## v2.2.106 — Setup Wizard: SPN-mode toggle (Create new vs Use existing)

The Tenant Identity step in the HTML wizard was forcing operators to enter an existing **App registration (client) ID GUID** — wrong default for a new-customer workflow, since the v2.2.105 backend can create the SPN automatically. Added the choice.

**New on the Tenant Identity page:**

- **SPN mode** toggle at the top: **Create new SPN** (default, recommended for newbies) | **Use existing SPN** (legacy / power-user).
- When **Create new** is selected:
  - The App ID GUID field is hidden — replaced with a single **SPN display name** input (e.g. `sp-securityinsight-myorg`).
  - Credential card switches to "Client secret / Self-signed certificate" (what to **generate**) plus a **cred storage** radio (`Azure Key Vault` *(preferred)* / `Local cert store` *(cert only)* / `Inline in custom.ps1` *(secret only)*).
  - Generated snippet preview shows a comment block describing what `/api/apply` will do on submit (creates app reg, generates cred, applies Graph + Azure perms, grants RBAC).
- When **Use existing** is selected: the original v2.2 form (App ID + KV name + secret name OR certificate thumbprint) is preserved verbatim — existing operators see no change.

Required-field validation is mode-aware: `tenantRequiredKeys()` now branches on `spnMode` so the Next button gates correctly per chosen path. State persists in `localStorage` like every other wizard answer.

**What's still pending:**
- HTML "Apply" page that POSTs the full state to `/api/apply` and renders progress UI — `v2.2.107`.
- Live log SSE streaming + drop Power BI / Workbook tabs — `v2.2.108`.

Until the Apply page lands, operators using **Create new** can drive the wizard's HTML to fill in all 10 pages, then trigger the apply directly via `Invoke-RestMethod -Method POST http://localhost:8766/api/apply -Body $stateJson` (the API is live since v2.2.105).

---

## v2.2.105 — Setup Wizard: backend cmdlets + `/api/apply` orchestration LIVE

The wizard's *Apply* page automation is now fully wired (backend side). Three new provisioner cmdlets do the entire onboarding end-to-end; `Start-SetupWizard.ps1`'s `/api/apply` endpoint chains them in sequence.

**`setup\ConfigWizard\backend\New-SISpn.ps1`** — provisions the SPN.
- Cred kinds: **Secret**, **Self-signed cert**, **Managed Identity** (the MSI branch reuses an existing MSI's SP and only grants the perms — no app-reg created).
- Cred storage: **Azure Key Vault** (preferred — secret as KV secret, cert as KV cert), **Local cert store** (cert path only — `CurrentUser\My`), **Inline** (secret only — returned to caller for direct write to `custom.ps1`).
- Idempotent: re-uses an existing app reg / SPN with the same display name; rotates the secret on every run.
- Grants Microsoft Graph application permissions (13-perm SI minimum: `ThreatHunting.Read.All`, `Device.Read.All`, `User.Read.All`, `Application.Read.All`, `Group.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`, `IdentityRiskEvent.Read.All`, `IdentityRiskyUser.Read.All`, `Reports.Read.All`, `DirectoryRecommendations.Read.All`, `SecurityEvents.Read.All`, `CrossTenantInformation.ReadBasic.All`) plus admin consent.
- Grants Azure RBAC at tenant-root MG: **Reader** + **Tag Contributor**.

**`setup\ConfigWizard\backend\Initialize-SIInfra.ps1`** — provisions LA + Storage.
- Creates Resource Group(s), Log Analytics Workspace, Data Collection Endpoint, Storage Account.
- Grants the SPN: **Log Analytics Contributor** on workspace, **Monitoring Metrics Publisher** on the DCR RG, **Storage Blob/Table/Queue Data Contributor** on the storage account.
- **RBAC-only storage** — engine reaches storage via OAuth; **no `SI_StorageKey` written to `custom.ps1`**. Same generated config works for VM-pinned and Container Apps Job hosts.
- Optional Key Vault provisioning (`-CreateKeyVault` switch) with RBAC for the SPN: Key Vault Secrets User + Key Vault Certificate User.
- Idempotent: existing resources are re-used.

**`setup\ConfigWizard\backend\Write-SICustomConfig.ps1`** — renders `config\SecurityInsight.custom.ps1`.
- Combines `New-SISpn` + `Initialize-SIInfra` outputs with the wizard's optional toggles (SMTP, Azure OpenAI, Shodan, CMDB CSV, per-engine JSON sink, Defender workspace ID).
- Backs up any existing `custom.ps1` to `*.bak.<timestamp>` before overwriting.
- Omits `SI_StorageKey` (RBAC-only mode).

**`Start-SetupWizard.ps1` `/api/apply` endpoint** — POSTs the wizard state JSON, runs the three cmdlets in sequence, returns a structured result with phase status (`spn` / `infra` / `config` each = `ok` / `failed` / `pending`), all provisioned resource IDs, and the run log. Failures localize: if the SPN succeeds but LA fails, the SPN block can still be written; the operator re-runs only the failed phase.

**What's NOT yet shipped** (next tags):
- HTML wizard's Tenant Identity step + Apply page UI changes — operators today call `/api/apply` directly via `Invoke-RestMethod` with their state JSON. Browser hookup lands in `v2.2.108`.
- Power BI + Azure Workbook tabs removed from the HTML — `v2.2.108`.
- Live log SSE streaming — `v2.2.108`.

---

## v2.2.104 — README: move Quick Start under "How to Implement", fix stale 3.X labels

The Three-step Quick Start section landed under § 3 ("What's supported") in v2.2.103 — wrong place; it's an implementation walkthrough so it belongs under § 4 ("How to Implement"). Fixed.

- Moved the Quick Start block under § 4 as the new **§ 4.1 Three-step quick start (recommended)**.
- All existing § 4 subsections were stale-labeled `3.X` from a prior refactor — renumbered to match the TOC: `3.1 → 4.2`, `3.2 → 4.3`, `3.3 → 4.4`, `3.4 → 4.5`, `3.5 → 4.6`, `3.6 → 4.7`, `3.7 → 4.8`, `3.8 → 4.9`, `3.9 → 4.10`, `3.10 → 4.11`, `3.11 → 4.12`. Nested `3.5.1..3.5.5` → `4.4.1..4.4.5`.
- TOC entries renumbered to match. New TOC entry `4.1 [Three-step quick start (recommended)]` added.
- Anchor `#41-three-step-quick-start-recommended` added; legacy anchor `#35-ten-step-newbie-setup` preserved so old deep-links still resolve.

---

## v2.2.103 — Setup Wizard: launcher skeleton + 3-step quick-start docs

First piece of the end-to-end Setup Wizard build. Future tags `v2.2.104..v2.2.109` add the provisioner cmdlets and the Apply page; this tag lays the foundation.

**What ships:**

- **`setup\ConfigWizard\Start-SetupWizard.ps1`** — PowerShell HttpListener that hosts the existing Config Wizard HTML on `http://localhost:8766`, opens the browser, and exposes `/api/state`, `/api/validate-name`, `/api/apply`, `/api/log-stream` as stubs. Same architecture as the SI viewer at `viewer/Start-SIViewer.ps1`. Runs on PS 5.1 + 7.x, Windows 10 / 11 / Server, on-prem and Azure-hosted.
- **`setup\ConfigWizard\ROADMAP.md`** — locked spec + per-tag delivery plan (`v2.2.103..v2.2.109`) for the Apply page automation: SPN auto-creation, cred type radio (secret / self-signed cert), cred storage (KV / local cert store / inline / Managed Identity), LA + DCE + DCRs + Storage with **RBAC-only** (no `SI_StorageKey` written to `custom.ps1`), and the optional toggles (SMTP / Azure OpenAI / Shodan / CMDB CSV / per-engine JSON sink).
- **README rewrite** of § 3.5 — replaces the 10-step ladder with a **three-step quick start**: clone → run wizard → run engines. Step 1 default points at the **stable** branch (`main`, not `preview`); zip URL too.
- **Doc-fix bonus** — Step 1 git/zip command lines use quoted args + `2>&1` redirect (matches what operators paste from corporate change-control templates) and `C:\SecurityInsightTest` as the example install path.

**What does NOT yet work:** the Apply page itself. POST to `/api/apply` returns `501 Not Implemented` until `v2.2.107` lands the orchestration. Until then, run the Wizard's HTML pages to generate config snippets and follow Steps 4–7 of the README (`Bootstrap-Auth.ps1` + `Bootstrap-Storage.ps1` + per-engine `LauncherConfig.custom.ps1` copy) — same actions, just one script per phase instead of one wizard click.

---

## v2.2.102 — README: same provider-list rewrite for the second blurb

The second copy of the headline blurb (further down the page) said "add-on to Microsoft Defender" — replaced with the same expanded provider list (Defender, Entra ID, AD, Azure, ExposureGraph) so both intro paragraphs match.

---

## v2.2.101 — README: hook-led intro + full provider list

Replaced the headline paragraph with a hook-led version: leads with "Rethink Secure Score into a risk-based score", names the full telemetry stack (MDE+XDR / MDI / Exposure Graph / Entra / on-prem AD / Azure Resource Graph / Shodan), keeps the "fix what an attacker would reach for first" hook, and closes with the asset-profiling engine + ready-to-use reports + executive summary + zero-footprint promises. Free / MVP-built / community-driven trails the value statement instead of leading it.

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

