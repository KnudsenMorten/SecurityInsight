# `demo/` — one-click refresh kit for the community demo env

Internal-only helper for refreshing the community demo VM with a known-good customer config snapshot. The `demo/community/` subfolder mirrors v2.2's customer-file layout and is **gitignored**, so it can hold real (working) values.

```
demo/
├── README.md                       # this file (tracked)
├── Install-DemoConfig.ps1          # tracked -- copies demo/community/* over the live config paths
└── community/                      # gitignored -- holds the actual customer config files
    ├── config/
    │   └── SecurityInsight.custom.ps1
    └── launcher/
        ├── endpoint/LauncherConfig.custom.ps1
        ├── identity/LauncherConfig.custom.ps1
        ├── azure/LauncherConfig.custom.ps1
        ├── publicip/LauncherConfig.custom.ps1
        ├── risk-analysis/LauncherConfig.custom.ps1
        └── privilege-tier-classifier/LauncherConfig.custom.ps1
```

## Quick refresh on the demo VM

```powershell
cd D:\AutomateIT\SOLUTIONS\SecurityInsight\demo
.\Install-DemoConfig.ps1
```

That copies every file under `community/` into the corresponding live path under `v2.2/`. The script overwrites without prompting (this folder is the source of truth for the demo env). Real installations should NOT run this — they edit their own `*.custom.ps1` directly.

## Refreshing the demo snapshot from a working VM

After tuning config on the demo VM, copy the live files back into `demo/community/`:

```powershell
.\Install-DemoConfig.ps1 -Direction FromLive
```

Then the next `git status` shows what changed. Files stay gitignored — the snapshot is just for your own backup / restore convenience.

## Use as Pester integration-test fixture

The integration test suite (`tests/integration/Invoke-IntegrationGate.ps1`) looks for `demo/community/config/SecurityInsight.custom.ps1` first to pick up real SPN/workspace values. If `demo/community/` is empty, the integration tests skip gracefully (they're opt-in by definition).

## Why gitignored

Files under `community/` may contain SPN secrets, real tenant IDs, real workspace names. Never tracked. The `Install-DemoConfig.ps1` helper IS tracked because it has no secrets — just file paths.
