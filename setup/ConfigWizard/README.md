# SecurityInsight v2.2 -- Config Wizard

A customer-facing, offline-first web wizard that drives the **entire** SecurityInsight onboarding from the browser. Type a tenant ID, accept a few defaults, click **Apply now** — and the wizard creates the SPN, provisions Log Analytics + DCE + Storage, and writes `config\SecurityInsight.custom.ps1` for you. No copy/paste, no PowerShell editing.

## Status

**End-to-end LIVE** as of `v2.2.107`. The Apply page POSTs the wizard's full state to `/api/apply` and renders 3-phase progress (SPN → Infrastructure → Config file).

| #  | Page                  | Status                       |
|----|-----------------------|------------------------------|
| 1  | Welcome               | Functional                   |
| 2  | Tenant identity       | Functional                   |
| 3  | Workspace + ingestion | Functional                   |
| 4  | Output sinks          | Coming in `v2.2.108`         |
| 5  | CMDB integration      | Coming in `v2.2.108`         |
| 6  | App / service tagging | Coming in `v2.2.108`         |
| 7  | RA exclusions         | Coming in `v2.2.108`         |
| 8  | Asset exclusion tags  | Coming in `v2.2.108`         |
| 9  | Shodan attack surface | Coming in `v2.2.108`         |
| 10 | Apply                 | **Functional** — POSTs `/api/apply`, 3-phase progress UI |

> Pages 4-9 are still placeholder cards; the Apply page works on the **required** state (Tenant + Workspace) and any optional sections you've configured via the JSON state. Once 4-9 land, every wizard answer flows through to the same Apply backend.

## Screenshots

| Step | Screenshot |
|------|------------|
| 1 — Tenant identity (SPN mode toggle, display name pre-filled) | ![Step 1](../../docs/screenshots/wizard/01-tenant-identity.png) |
| 2 — Workspace + ingestion (workspace name + RG + DCE all pre-filled) | ![Step 2](../../docs/screenshots/wizard/02-workspace-ingestion.png) |
| 10 — Apply page before clicking | ![Step 10 — before](../../docs/screenshots/wizard/10-apply-page.png) |
| 10 — Apply page after success (all 3 phases green) | ![Step 10 — success](../../docs/screenshots/wizard/10-apply-success.png) |

## Run it

```powershell
.\setup\ConfigWizard\Start-SetupWizard.ps1
```

This starts a localhost-only `HttpListener` at `http://localhost:8766`, opens it in your default browser, and exits when you stop the listener (`Ctrl+C` in the PowerShell window).

The listener exposes:
- `GET /` -- the wizard HTML (all assets served from disk, no remote URLs).
- `GET /api/state` -- introspection: which backend cmdlets are present, whether `/api/apply` is callable.
- `POST /api/apply` -- the workhorse. Accepts the wizard state JSON, runs `New-SISpn` → `Initialize-SIInfra` → `Write-SICustomConfig` → `Set-SIEntraDiagnosticSetting` (Phase 4, gated on the wizard toggle, default ON) in sequence, returns `{ ok, phase, phaseStatus, spn, infra, configFile, entraDiag, log }`.
- `POST /api/validate-name` -- name-format check (stub; client-side validation already covers most cases).
- `GET /api/log-stream` -- SSE event stream (stub; lights up in `v2.2.108`).

You can also POST directly to `/api/apply` from PowerShell if you want to drive the backend from a script:

```powershell
$state = @{
  tenantId       = '<tenant-guid>'
  subscriptionId = '<sub-guid>'
  spn = @{ displayName = 'sp-securityinsight-myorg'; credKind = 'Secret'; credStorage = 'KeyVault'; keyVaultName = 'kv-myorg-securityinsight' }
  infra = @{ location = 'westeurope'; resourceGroupName = 'rg-securityinsight'; workspaceName = 'log-platform-management-securityinsight'; dceName = 'dce-securityinsight'; storageAccountName = 'stsecurityinsightmyorg' }
} | ConvertTo-Json -Depth 6
Invoke-RestMethod -Method POST http://localhost:8766/api/apply -ContentType application/json -Body $state
```

## Design principles

- **No build step.** Plain HTML, CSS, JS. Open in any browser.
- **Offline.** Zero remote URLs. No CDN. No web fonts. No fetch beyond `localhost`.
- **Persistent.** Every answer is saved to `localStorage` under the key `si.v22.wizard.state.v1`. Close the tab, reopen -- you're back where you were. The Welcome page has a Reset button that wipes it.
- **Pre-filled defaults.** Recommended values for the SPN display name, Key Vault secret name, workspace name + RG, and DCE name + RG are seeded into the input fields on first load — newcomers can click Next → Next → Apply without typing anything besides the GUIDs that have to come from their own tenant.
- **Validated.** GUID, hex-thumbprint, Key Vault name format are all validated inline as you type.
- **Snippet preview.** Each functional page renders a live PowerShell snippet on the right; click "Copy snippet" to put it on the clipboard. Lines whose value still matches the recommended default carry a `# default` tag.
- **Secret-redacted state preview** on the Apply page — SMTP / OpenAI / Shodan API keys are rendered as `***` in the JSON shown to the operator.

## Branding

- Dark navy `#1a3a5c` primary, teal `#2a8b9b` accent.
- System font stack (`-apple-system, Segoe UI, Inter, system-ui`) -- no web font downloads.
- Inline SVG shield in the header (no external image dependency).
- 8px rounded corners, subtle shadows, smooth 150ms transitions.
- Palette is intentionally aligned with the `Setup-SecurityInsight.ps1` console output (cyan / green / yellow) so the two surfaces feel like siblings.

## File layout

```
setup/ConfigWizard/
  Setup-SecurityInsight.html -- SPA shell, one <section class="page"> per wizard page
  styles.css                 -- single stylesheet, themed via CSS custom properties
  app.js                     -- wizard state machine, validators, snippet generators, Apply page
  Start-SetupWizard.ps1      -- HttpListener that hosts the HTML + exposes /api/* endpoints
  ROADMAP.md                 -- per-tag delivery plan
  README.md                  -- this file
  backend/
    New-SISpn.ps1                    -- provisions the Entra app reg + SP + cred + Graph perms + RBAC
    Initialize-SIInfra.ps1           -- provisions LA workspace + DCE + Storage (RBAC-only)
    Write-SICustomConfig.ps1         -- renders config\SecurityInsight.custom.ps1 from collected state
    Set-SIEntraDiagnosticSetting.ps1 -- creates tenant-level Entra ID Diagnostic Setting (Phase 4)
```

## Extending: adding a new functional page

1. In `app.js`'s `PAGES` array, flip the matching page's `active: false` to `true` (or add a new entry).
2. Add the matching `<section class="page" data-page="<id>">` to `Setup-SecurityInsight.html` -- copy an existing functional page's structure (header + form cards + preview card).
3. Inputs should carry `data-key="<stateKey>"` so they auto-bind to `state.data` and persist via `localStorage`. Add `data-default="<recommended>"` on inputs that have a sensible default — they will be pre-filled into the input on first load and tagged `# default` in the snippet preview.
4. Add validator(s) to the `validators` map in `app.js` if any input needs format validation; emit an inline error span via `<span class="err" data-err="<stateKey>">...</span>`.
5. Implement a `buildXxxSnippet()` function and register it in `SNIPPET_BUILDERS` keyed by page id. Render target is `<pre class="preview" id="preview-<pageId>">`.
6. If the new page produces optional state that the Apply backend should consume, extend `buildApplyState()` in `app.js` to include the new keys, and extend the relevant backend cmdlet (`New-SISpn` / `Initialize-SIInfra` / `Write-SICustomConfig`) to honour them.

The "done" badge in the rail flips automatically once `isPageDone(pageId)` returns true -- update `PAGE_REQS` (or the dynamic `tenantRequiredKeys`-style helper) to reflect what counts as "complete" for the new page.
