# SecurityInsight v2.2 -- Config Wizard

A customer-facing, offline-first web wizard that walks through generating
every `*.custom.*` override file the SecurityInsight v2.2 engines need.

## Status

This is the **scaffold** delivery. 3 pages are functional end-to-end; the
remaining 7 are placeholder cards in the left rail with a "Coming soon" badge.

| #  | Page                  | Status      |
|----|-----------------------|-------------|
| 1  | Welcome               | Functional  |
| 2  | Tenant identity       | Functional  |
| 3  | Workspace + ingestion | Functional  |
| 4  | Output sinks          | Coming soon |
| 5  | CMDB integration      | Coming soon |
| 6  | App / service tagging | Coming soon |
| 7  | RA exclusions         | Coming soon |
| 8  | Asset exclusion tags  | Coming soon |
| 9  | Shodan attack surface | Coming soon |
| 10 | Advanced overrides    | Coming soon |
| 11 | Review & generate     | Coming soon |

## Run it

```powershell
cd C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\v2.2
.\Setup-SecurityInsight.ps1 -Wizard
```

The `-Wizard` switch on `Setup-SecurityInsight.ps1` opens `setup\ConfigWizard\Setup-SecurityInsight.html`
in your default browser via `Start-Process` and exits (no phases run). Add
`-NoBrowser` to print the `file://` URL only.

You can also just double-click `Setup-SecurityInsight.html` -- the wizard is
pure static HTML/CSS/JS and runs straight from the file system.

## Design principles

- **No build step.** Plain HTML, CSS, JS. Open in any browser.
- **Offline.** Zero remote URLs. No CDN. No web fonts. No fetch.
- **Persistent.** Every answer is saved to `localStorage` under the key
  `si.v22.wizard.state.v1`. Close the tab, reopen -- you're back where you
  were. The Welcome page has a Reset button that wipes it.
- **Validated.** GUID, hex-thumbprint, Key Vault name format are all
  validated inline as you type.
- **Snippet preview.** Each functional page renders a live PowerShell
  snippet on the right; click "Copy snippet" to put it on the clipboard.

## Branding

- Dark navy `#1a3a5c` primary, teal `#2a8b9b` accent.
- System font stack (`-apple-system, Segoe UI, Inter, system-ui`) -- no web
  font downloads.
- Inline SVG shield in the header (no external image dependency).
- 8px rounded corners, subtle shadows, smooth 150ms transitions.
- Palette is intentionally aligned with the `Setup-SecurityInsight.ps1`
  console output (cyan / green / yellow) so the two surfaces feel like
  siblings.

## File layout

```
setup/ConfigWizard/
  Setup-SecurityInsight.html -- SPA shell, one <section class="page"> per wizard page
  styles.css                 -- single stylesheet, themed via CSS custom properties
  app.js                     -- wizard state machine, validators, snippet generators
  README.md                  -- this file
```

## Extending: adding a new functional page

1. Add an entry to the `PAGES` array in `app.js` (or flip an existing one's
   `active: false` to `true`).
2. Add the matching `<section class="page" data-page="<id>">` to
   `Setup-SecurityInsight.html` -- copy an existing functional page's
   structure (header + form cards + preview card).
3. Inputs should carry `data-key="<stateKey>"` so they auto-bind to
   `state.data` and persist via `localStorage`.
4. Add validator(s) to the `validators` map in `app.js` if any input needs
   format validation; emit an inline error span via
   `<span class="err" data-err="<stateKey>">...</span>`.
5. Implement a `buildXxxSnippet()` function and register it in
   `SNIPPET_BUILDERS` keyed by page id. Render target is
   `<pre class="preview" id="preview-<pageId>">`.

The "done" badge in the rail flips automatically once `isPageDone(pageId)`
returns true -- update `PAGE_REQS` (or the dynamic `tenantRequiredKeys`-style
helper) to reflect what counts as "complete" for the new page.

## File-write strategy

The current scaffold is **copy-paste only** -- the customer copies each
generated snippet into the indicated `*.custom.*` file path. The next
iteration will turn `Setup-SecurityInsight.ps1 -Wizard` into a tiny local
HTTP listener (HttpListener, no external deps) so the wizard's Review page
can POST the assembled config to it and the launcher writes the files to
disk. That keeps the wizard's "no remote fetch" guarantee intact while
removing the manual copy step.
