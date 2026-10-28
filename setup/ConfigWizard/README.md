# SecurityInsight -- Config Wizard

A customer-facing, offline-first web wizard that drives the **entire** SecurityInsight onboarding from the browser. Type a tenant ID, accept a few defaults, click **Apply now** — and the wizard creates the SPN, provisions Log Analytics + DCE + Storage, and writes `config\SecurityInsight.custom.ps1` for you. No copy/paste, no PowerShell editing.

## Status

All pages are live. **Setup** POSTs the wizard's full state to `/api/apply` and shows each provisioning phase (service principal → infrastructure → config file → Entra diagnostic setting) with its own log. Re-running the wizard on an existing install keeps every value in `config\SecurityInsight.custom.ps1` and adds only the settings it does not have yet (a backup of the previous file is written first).

| Page | What you set |
|---|---|
| Welcome | — |
| Tenant identity | the sign-in: a **managed identity** by default (user-assigned: created, granted and attached to the VM you name; for Container Apps the jobs' own identity). A service principal when you choose it: create new or use existing, certificate (recommended) or secret, where the credential is kept; optionally allow asset tagging (Tag Contributor). A server outside Azure has no managed identity: there the page says so and offers a certificate first, then a secret |
| Workspace + ingestion | Log Analytics workspace, resource group, data collection endpoint, storage |
| Mail / SMTP | relay and recipients for the Risk Analysis mails |
| CMDB integration | CMDB file and matching |
| Azure OpenAI | AI classification and the executive summary (optional) |
| Shodan attack surface | public-IP scanning (optional) |
| Output sinks + Defender | output sinks, Defender for Cloud collection |
| Setup | review and provision |
## Run it

```powershell
.\setup\ConfigWizard\Start-SetupWizard.ps1
```

This starts a localhost-only `HttpListener` at `http://localhost:8766`, opens it in your default browser, and exits when you stop the listener (`Ctrl+C` in the PowerShell window).

The listener exposes:
- `GET /` -- the wizard HTML (all assets served from disk, no remote URLs).
- `GET /api/state` -- introspection: which backend cmdlets are present, whether `/api/apply` is callable.
- `POST /api/apply` -- the workhorse. Accepts the wizard state JSON, runs `New-SISpn` → `Initialize-SIInfra` → `Write-SICustomConfig` → `Set-SIEntraDiagnosticSetting` (phase 4, gated on the wizard toggle, default on) in sequence, returns `{ ok, phase, phaseStatus, spn, infra, configFile, entraDiag, log }`.
- `POST /api/validate-name` -- name-format check (stub; client-side validation already covers most cases).
- `GET /api/log-stream` -- SSE event stream (stub).

You can also POST directly to `/api/apply` from PowerShell if you want to drive the backend from a script:

```powershell
$state = @{
  tenantId       = '<tenant-guid>'
  subscriptionId = '<sub-guid>'
  hostType       = 'azureVMMI'
  # no credKind = the default, a user-assigned managed identity (attached to vmName when given).
  # A service principal instead: credKind = 'Cert' (recommended) or 'Secret', with displayName + credStorage.
  spn = @{ managedIdentityName = 'id-si-prod-community-vm'; vmName = 'vm-securityinsight'; vmResourceGroup = 'rg-servers' }
  infra = @{ location = 'westeurope'; resourceGroupName = 'rg-securityinsight'; workspaceName = 'log-platform-management-securityinsight'; dceName = 'dce-securityinsight'; storageAccountName = 'stsecurityinsightmyorg' }
} | ConvertTo-Json -Depth 6
Invoke-RestMethod -Method POST http://localhost:8766/api/apply -ContentType application/json -Body $state
```

## Changing settings after setup

This wizard is first-time setup only. Community: change settings in the custom files (`docs/DESIGN.md`, "Changing settings"). SecurityInsight Pro changes them in its web app.

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
- Palette is intentionally aligned with the setup scripts' console output (cyan / green / yellow) so the two surfaces feel like siblings.

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
