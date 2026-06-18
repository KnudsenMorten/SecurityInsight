# SecurityInsight Analyzer (SIA) — hosted web app

Executive-grade, **hosted** analyzer over the SecurityInsight Risk-Analysis (RA) data.
ASP.NET Core (C#), reusing the proven CEH stack patterns. Built by porting the proven
PowerShell POC logic (`../analyzer/lib/SiAnalyzer-*.ps1`) — the read-only KQL guardrail,
the snapshot diff + score timeline, the grounded AI prompts — into a real web app.

> **Status: built, not live-verified.** The hosted run (real internal workspace + AI-on +
> Entra sign-in) is the release gate. See `../docs/REQUIREMENTS.md` "SI Analyzer".

## Audience & surfaces
- **Executive (default landing, `/exec`)** — board-ready, plain-language, chart-led:
  headline risk-score dial + direction, trend with a **labelled forecast**, severity/area
  donuts, top risks + wins, **quick-wins/ROI**, coverage & confidence, period-over-period.
  Mobile-friendly, accessible, print/PDF-friendly. **No KQL/jargon.**
- **Analyst (`/analyst`)** — the prompt box (exec + analyst tone), one-click prestaged
  analyses, a guarded raw-KQL box, drill-down. Technical depth lives here.
- **MCP server (`POST /mcp`)** — read-only, guardrailed JSON-RPC tools mirroring the
  prestaged analyses + a guarded query + snapshot/diff/timeline/exec-summary.

## Data plane & AI
- **Read-only** Azure Monitor Query SDK against the internal SI workspace via **Managed
  Identity** (Log Analytics Reader). The **internal env is the default base**; demo data is
  the explicit fallback.
- **Azure OpenAI** narrative, **grounded** strictly in the returned KQL facts, **AI-on by
  default** in the hosted internal env, **fail-soft** to a templated summary.
- Every query (prestaged, ad-hoc, raw, MCP) passes the **read-only guardrail** first.

## Layout
```
analyzer-web/
  src/Sia.Core/      ported logic (guardrail, KQL builders, prestaged, diff/timeline, AI prompts, exec rollup)
  src/Sia.Web/       ASP.NET Core app (exec + analyst pages, JSON API, MCP, data plane, AI service)
  tools/Sia.Preview/ renders the exec dashboard to a static preview HTML
  tests/Sia.Tests/   xunit offline tests (guardrail, grounding, diff/timeline, resolver, MCP, exec-default)
  deploy/            Dockerfile + Deploy-SiaAnalyzer.ps1 + README-DEPLOY.md (MI grant + Easy Auth)
  preview/           committed static exec-dashboard.html (open locally, no server)
```

## Run / build / test / preview
```powershell
dotnet build analyzer-web/Sia.sln -c Release
dotnet test  analyzer-web/Sia.sln -c Release

# Live local preview (demo data, AI-off):
dotnet run --project analyzer-web/src/Sia.Web        # then open http://localhost:5xxx/

# Regenerate the committed static preview (no server):
dotnet run --project analyzer-web/tools/Sia.Preview  # writes analyzer-web/preview/exec-dashboard.html
```

## Deploy
See `deploy/README-DEPLOY.md` for the exact deploy command, the Managed-Identity →
Log Analytics Reader grant, and the Easy Auth setup. The **main session** deploys.
