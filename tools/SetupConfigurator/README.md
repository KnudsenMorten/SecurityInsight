# SecurityInsight — Setup Configurator

A zero-dependency, single-file HTML tool that helps you build `LauncherConfig.custom.ps1` files for each Step + ingestion engine.

## Use it

```powershell
# From anywhere (Windows):
Start-Process 'C:\SCRIPTS\SecurityInsight\TOOLS\SetupConfigurator\index.html'

# Or just double-click index.html in Explorer.
# Works offline -- no server, no Node, no Python.
```

## What it does

- Four tabs — Step 1, Step 2, Step 3, ingestion engines.
- Fill in the form fields on the left; a ready-to-paste `LauncherConfig.custom.ps1` renders live on the right.
- **Copy to clipboard** or **Download** the generated file.
- Shows the **Layer 0 shared defaults** inline so you can see what you're inheriting vs. overriding.
- Auth-method selector (SPN+Secret, SPN+Cert, SPN+KV, Managed Identity) dynamically shows / hides the right input fields.

## Where it sends your data

**Nowhere.** All processing happens in-browser. The file is pure HTML + vanilla JavaScript — no network calls, no analytics, no third-party scripts. You can open DevTools → Network to confirm.

Secrets typed into the form never leave your browser tab. They go into the generated PowerShell (which you then save wherever you want). If you don't want plaintext secrets in your preview, use the SPN+KV or Managed Identity auth option.

## Roadmap

- Aggregate view: show the effective value for every `$global:*` across all 5 config layers (Layer 0 shared → Layer 1 per-engine → Layer 2 platform → Layer 3 solution-custom → Layer 4 launcher-custom) so you can see where each value actually comes from.
- Live validation: detect obviously-wrong GUIDs, non-existent Azure regions, etc.
- Step 0 launcher: embed the PowerShell bootstrap command directly in the page with a copy button.
- Offline PWA wrapper so the tool can be pinned on the Start menu.
