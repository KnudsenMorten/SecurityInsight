# `config/` — solution-wide customer config (Layer 3)

This folder holds the **single solution-wide override file** for SecurityInsight v2.2:

```
config/
├── SecurityInsight.custom.sample.ps1   # tracked  -- annotated template (copy from)
├── SecurityInsight.custom.ps1          # gitignored -- your tenant-specific overrides
└── README.md                            # this file
```

## Layered config model (each layer overrides the previous)

| Layer | File | Owned by | Tracked? |
|---|---|---|---|
| 0 | `launcher/_lib/SecurityInsight.shared-defaults.ps1` | Platform | ✓ |
| 1 | `launcher/<engine>/LauncherConfig.defaults.ps1` | Platform (per-engine baseline) | ✓ |
| 2 | `config/SecurityInsight.custom.ps1` | **Customer** (solution-wide) | ✗ gitignored |
| 3 | `launcher/<engine>/LauncherConfig.custom.ps1` | Customer (per-engine override) | ✗ gitignored |
| 4 | CLI args on the launcher invocation | Caller | n/a |

Each layer wins over the previous. Set values at the **lowest layer that makes sense** so that more specific intent is closer to the call site.

## How customers use this folder

1. On first install, copy `SecurityInsight.custom.sample.ps1` → `SecurityInsight.custom.ps1` (same folder).
2. Edit the copy: set tenant, workspace, mail recipients, AI toggles — **anything that should apply to every SI engine**.
3. The engines auto-detect this file at startup via `Initialize-LauncherConfig`. No path needs to be passed.

## What goes here (vs Layer 3 per-engine)

**Layer 2 (this file)** — anything you want EVERY engine to see:
- SPN tenant + KeyVault name + secret name
- Workspace + DCE + DCR resource groups
- Mail / SMTP defaults
- `$global:SI_EnableAI`, `$global:SI_HostMode` etc.

**Layer 3 (`launcher/<engine>/LauncherConfig.custom.ps1`)** — only when ONE engine needs to differ:
- A different mail recipient for Critical-only RA
- A different output path for endpoint scans
- An engine-specific `AssetLimit` for testing

If 90% of customers will set a value, it belongs in this file.
