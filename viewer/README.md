# SecurityInsight Risk Analysis Viewer (test rig)

Tiny local-only web UI for browsing the JSON output of `Invoke-RiskAnalysis.ps1` — pivot, multi-filter, full-text search, and a KPI strip showing the global Risk Score plus per-domain breakdown.

**No IIS, no auth, no cloud.** Just a PowerShell HttpListener bound to `localhost`. This is the prototype to evaluate the experience before deciding whether to host it under IIS with Entra ID.

## What you get

- **KPI strip** — Global Risk Score (0–100) with color-coded level pill + 4 domain tiles (Endpoint, Identity, Azure, PublicIP). Math mirrors the engine.
- **Grid** — ag-Grid Community: per-column filters, floating filters, drag-to-group panel, pagination, severity/tier color coding, links live in `MoreDetails`.
- **Pivot** — PivotTable.js: drag any column to rows/cols, switch aggregator, heatmap renderer. Defaults to *SecurityDomain × SecuritySeverity*.
- **Top-bar filters** — Domain / Severity / Tier dropdowns + a global search box; both pipe into ag-Grid's filter model.
- **File picker** — auto-discovers every `RiskAnalysis_*.json` in the SI `output/` folder, sorted newest first.

## Requirements

- Windows PowerShell 5.1 or later (no extra modules).
- Network port (default `8765`) free on the VM.
- Internet on first load — pulls ag-Grid, jQuery, and PivotTable.js from `cdn.jsdelivr.net`. To go offline, vendor those files into `web/` and update the `<script>`/`<link>` paths.

## Run

```powershell
cd C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\viewer
.\Start-SIViewer.ps1
```

The script binds `http://localhost:8765/`, opens your default browser, and tails its own request log to the console. Stop with **Ctrl+C**.

```powershell
# different port
.\Start-SIViewer.ps1 -Port 9000

# point at a different output folder (e.g. customer dump)
.\Start-SIViewer.ps1 -OutputDir D:\customers\evida\latest

# headless (no auto-launch browser)
.\Start-SIViewer.ps1 -NoBrowser
```

## Endpoints

| Path | Returns |
|------|---------|
| `/`                         | the viewer HTML |
| `/api/files`                | JSON list of `RiskAnalysis_*.json` files in `OutputDir` (newest first) |
| `/api/data?file=<name>`     | raw JSON content of one file (path-traversal guarded) |
| `/health`                   | liveness probe |

## Security model

- Listener binds **`localhost` only** — no remote machine on the network can reach it.
- No authentication. Anyone signed into the VM can hit `http://localhost:8765/`.
- **Don't put this on a multi-user server.** When you're ready for that, move the `web/` folder under IIS, drop in MSAL.js for Entra sign-in, and delete `Start-SIViewer.ps1`.

## Troubleshooting

**"Access is denied" when starting** — Windows requires either admin rights or a URL ACL to bind a non-loopback prefix. The default `http://localhost:<port>/` form usually works for the current user; if it doesn't, run **once as admin**:

```powershell
netsh http add urlacl url=http://localhost:8765/ user="$env:USERDOMAIN\$env:USERNAME"
```

…and afterwards you can run the viewer normally.

**"No JSON files found"** — the script defaults to `<solution>/output/`. Confirm that `Invoke-RiskAnalysis.ps1` has actually produced `RiskAnalysis_*.json` there (`$global:WriteJsonOutput = $true`, default), or pass `-OutputDir <path>` explicitly.

**Grid loads but columns look wrong** — the grid samples the first 50 rows for column discovery. If your JSON has highly heterogeneous rows, edit `web/index.html` and bump that limit (search for `slice(0, 50)`).

## What's next

- IIS deployment with MSAL.js + Entra ID app registration (group-based access)
- Optional: drop the file picker and stream live from `SI_RiskAnalysis_Detailed_CL` via the LA query API
- Optional: inline a 31-day Risk Score trend chart (pulls `SI_RiskScore_CL`)
