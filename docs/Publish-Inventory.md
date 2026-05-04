# Publish inventory — what ships vs what stays internal

Two questions answered here:
1. **What gets pushed** to the public preview repo (`KnudsenMorten/SecurityInsight`, `preview` branch) when the publish workflow fires.
2. **What stays internal** (gitignored on the monorepo, never touches the public repo).

---

## ✅ Files / folders that DO publish to the public preview repo

The publish workflow's **v2.2-layout staging** step (in `.github/workflows/publish.yml`) mirrors the entire `SOLUTIONS/SecurityInsight/` tree verbatim into the staged output, **except** the runtime/internal folders explicitly listed below.

| Path under `v2.2/` | Why it ships |
|---|---|
| `Bootstrap-Auth.ps1` | Customer entrypoint — provisions SPN |
| `Bootstrap-Storage.ps1` | Customer entrypoint — provisions LA + Storage |
| `Bootstrap-ContainerAppJob.ps1` | Customer entrypoint — container/KEDA mode |
| `Setup-SecurityInsight.ps1` | Single-entry setup orchestrator (phases + `-Wizard` GUI) |
| `Get-FingerprintEngine.ps1` | Engine version stamp |
| `VERSION` | Semver string |
| `README.md` | The reader's first stop |
| `RELEASENOTES.md` | Curated changelog |
| `auth/` | SPN / Graph token helpers (engine-side, dot-sourced) |
| `engine/` | All engine code (asset-profiling, risk-analysis, publicip, privilege-tier-classifier) |
| `launcher/` | Per-engine launchers (community-vm + internal-vm flavours) |
| `setup/` | Step0 → Step4 onboarding scripts |
| `container/` | Dockerfile + entrypoints for KEDA mode |
| `data/` | Sample data files (CMDB, RiskIndex, etc.) |
| `docs/` | Permanent reference docs (ARCHITECTURE / Operations / PROVIDER_CONTRACT / asset-profiling-schema / risk-analysis-detection / CMDB-customer-drop / PREVIEW) |
| `tools/` | Customer-facing helpers (e.g. `Push-PreviewBundle.ps1`) |
| `tests/` | Smoke tests + audit helpers (transparent — no secrets) |
| `legacy/` | The legacy `CriticalAssetTagging` engine, opt-in for tag writes |
| `preview/` | Power BI + Azure Workbook templates |
| `privilege-tier-catalog/` | Locked tier catalog JSON + curated CMDB sample |
| `asset-profiling-schema/*.locked.json` | Locked profile schemas (3) + the root SCHEMA |
| `asset-profiling-schema/*.custom.sample.json` | Sample for customer extensions |
| `asset-profiling-providers/_manifest.schema.locked.json` | Provider manifest schema |
| `asset-profiling-providers/entra/*.ps1` | Built-in Entra provider |
| `asset-profiling-providers/servicenow-cmdb/Refresh-CmdbCache.ps1` | CMDB pull script |
| `asset-profiling-providers/servicenow-cmdb/sample/CMDB.csv` | Sample CMDB CSV (column reference) |
| `asset-profiling-enrichment/**/*.locked.yaml` | All 559 locked enrichment rules |
| `asset-profiling-enrichment/**/*.custom.sample.yaml` | All 564 sample customizations (documentation) |
| `risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml` | All 110 RA report definitions |
| `risk-analysis-detection/risk-analysis.schema.locked.json` | RA report schema |
| `risk-analysis-detection/riskscore_weighted.schema.custom.sample.json` | Sample weighted-score config |
| `risk-analysis-detection/*.exclude.json.sample` | Sample exclusion files |
| `FUNCTIONS/AutomateITPS*` | Bundled at publish time from monorepo `FUNCTIONS/` (community customers need it inlined) |

---

## ⛔ Files / folders that DO NOT publish (excluded by the workflow)

| Path | Reason |
|---|---|
| `logs/` | Per-run transcripts — environment-specific, often contain timestamps + tenant IDs |
| `staging/` | Internal AI signal-map cache + transient state — regenerated each run |
| `risk-analysis-detection/OUTPUT/` | Customer's xlsx + JSON output — runtime artefacts |
| `README.PLAN.md` | Internal planning doc |
| `data/_samples/` (any large binaries) | Not strictly excluded; review before push if size matters |

The publish workflow's v2.2-layout step explicitly excludes `logs`, `OUTPUT`, `staging` directories (top-level under `v2.2/`).

---

## 🔒 Files that MUST be gitignored (never enter the monorepo)

These are customer-specific and may contain secrets or tenant-specific overrides. They should never be tracked — even on the internal monorepo — because once committed they'd ship through publish.

### Currently missing from `.gitignore` ⚠️

The current root `.gitignore` covers `providers-custom/` and `rules-custom/` (legacy paths). **The v2.2 layout uses different paths** that are NOT yet ignored:

| Pattern | What it covers | Files currently leaking |
|---|---|---|
| `SOLUTIONS/SecurityInsight/asset-profiling-enrichment/**/*.custom.yaml` | Customer-tuned enrichment rules | 6 files tracked: AssetProfileByTags, VisualCron, AssetProfileByIPSubnet, AssetProfileByExtensionAttributes, AssetProfileByGroupMembership, AssetProfileByCmdbTag |
| `SOLUTIONS/SecurityInsight/asset-profiling-enrichment/**/*.custom.yml` | Same, .yml variant | 0 currently |
| `SOLUTIONS/SecurityInsight/asset-profiling-providers/**/CMDB.csv` | Customer's CMDB extract (NOT the sample) | 1 file tracked: `servicenow-cmdb/CMDB.csv` |
| `SOLUTIONS/SecurityInsight/risk-analysis-detection/*.exclude.custom.json` | Per-report customer exclusions | 12 files tracked |
| `SOLUTIONS/SecurityInsight/risk-analysis-detection/riskscore_weighted.schema.custom.json` | Customer weight overrides | 1 file tracked |
| `SOLUTIONS/SecurityInsight/asset-profiling-schema/*.custom.json` | Customer schema extensions (excluding `.sample.`) | 1 file tracked: `public-ip.schema.custom.json` |
| `SOLUTIONS/SecurityInsight/launcher/*/LauncherConfig.custom.ps1` | Per-engine launcher overrides — may contain SPN secrets | 2 files tracked: `publicip/`, `risk-analysis/` |
| `!**/*.custom.sample.*` | Negation: SAMPLE files DO ship | — |
| `SOLUTIONS/SecurityInsight/config/SecurityInsight.custom.ps1` | Customer's main config — **contains SPN client secret** | (already covered by existing `SOLUTIONS/*/config/*` rule) |

### Already covered by existing patterns

- `SOLUTIONS/*/config/*` (with negation for `*.sample.*` and `README.md`)
- `SOLUTIONS/*/DATA/OUTPUT/`
- `OUTPUT/` (any depth)

---

## 🛠️ Action items

### 1. Patch `.gitignore` immediately

Add this block to root `.gitignore`:

```gitignore
# v2.2 layout customer-owned files — never publish, never commit
SOLUTIONS/SecurityInsight/asset-profiling-enrichment/**/*.custom.yaml
SOLUTIONS/SecurityInsight/asset-profiling-enrichment/**/*.custom.yml
SOLUTIONS/SecurityInsight/asset-profiling-providers/**/CMDB.csv
SOLUTIONS/SecurityInsight/risk-analysis-detection/*.exclude.custom.json
SOLUTIONS/SecurityInsight/risk-analysis-detection/*.custom.json
SOLUTIONS/SecurityInsight/risk-analysis-detection/*.custom.yaml
SOLUTIONS/SecurityInsight/asset-profiling-schema/*.custom.json
SOLUTIONS/SecurityInsight/launcher/*/LauncherConfig.custom.ps1
SOLUTIONS/SecurityInsight/logs/
SOLUTIONS/SecurityInsight/staging/
SOLUTIONS/SecurityInsight/risk-analysis-detection/OUTPUT/
# Re-affirm sample files DO ship (samples are documentation, not customer data)
!SOLUTIONS/SecurityInsight/**/*.custom.sample.yaml
!SOLUTIONS/SecurityInsight/**/*.custom.sample.yml
!SOLUTIONS/SecurityInsight/**/*.custom.sample.json
!SOLUTIONS/SecurityInsight/**/*.custom.sample.ps1
!SOLUTIONS/SecurityInsight/asset-profiling-providers/**/sample/CMDB.csv
!SOLUTIONS/SecurityInsight/risk-analysis-detection/*.exclude.json.sample
```

### 2. Untrack files already in git (after .gitignore patch)

```powershell
# Remove from git index but keep on disk
$files = @(
    'SOLUTIONS/SecurityInsight/asset-profiling-enrichment/azure/AssetProfileByTags.custom.yaml',
    'SOLUTIONS/SecurityInsight/asset-profiling-enrichment/endpoint/AssetProfileByApplicationServiceDetection/VisualCron.custom.yaml',
    'SOLUTIONS/SecurityInsight/asset-profiling-enrichment/endpoint/AssetProfileByIPSubnet.custom.yaml',
    'SOLUTIONS/SecurityInsight/asset-profiling-enrichment/identity/AssetProfileByExtensionAttributes.custom.yaml',
    'SOLUTIONS/SecurityInsight/asset-profiling-enrichment/identity/AssetProfileByGroupMembership.custom.yaml',
    'SOLUTIONS/SecurityInsight/asset-profiling-enrichment/shared/AssetProfileByCmdbTag.custom.yaml',
    'SOLUTIONS/SecurityInsight/asset-profiling-providers/servicenow-cmdb/CMDB.csv',
    'SOLUTIONS/SecurityInsight/risk-analysis-detection/riskscore_weighted.schema.custom.json',
    'SOLUTIONS/SecurityInsight/asset-profiling-schema/public-ip.schema.custom.json',
    'SOLUTIONS/SecurityInsight/launcher/publicip/LauncherConfig.custom.ps1',
    'SOLUTIONS/SecurityInsight/launcher/risk-analysis/LauncherConfig.custom.ps1'
)
# Plus all 12 *.exclude.custom.json under risk-analysis-detection/
$files += (Get-ChildItem 'SOLUTIONS/SecurityInsight/risk-analysis-detection/*.exclude.custom.json' | ForEach-Object { $_.FullName -replace '^.*AutomateIT[\\/]','' -replace '\\','/' })
foreach ($f in $files) { git rm --cached $f 2>$null }
git commit -m "chore(SI v2.2): untrack customer-owned .custom.* files (now properly gitignored)"
```

### 3. Verify with a dry-run publish

```powershell
# Trigger publish workflow with dryRun=true via workflow_dispatch
# - solution=SecurityInsight, version=2.2.0, preview=true, dryRun=true
# Then download the artifact and verify NO .custom.* files (without .sample.) appear in the staged output
```

---

## Summary cheat sheet

| Bucket | Count today | Action |
|---|---|---|
| 🟢 Files that publish | ~1100+ (entire v2.2/ minus exclusions) | None — already correct |
| 🟡 Files that should publish but might be missed | 0 | None |
| 🔴 Files leaking into monorepo (need .gitignore + git rm --cached) | **11 tracked** (+12 `.exclude.custom.json` on disk but not yet tracked — gitignore prevents future entry) | Apply patches in §1+§2 above |
| ⛔ Files that should never be ignored (samples / documentation) | All `*.sample.*` | Already negated in patches |
