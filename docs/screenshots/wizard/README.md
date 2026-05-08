# Setup Wizard screenshots

Drop these PNGs into this folder. Filenames must match exactly — they're referenced from the SI README §4.1 + `setup/ConfigWizard/README.md`.

| Filename                              | What to capture                                                                                  |
|---------------------------------------|--------------------------------------------------------------------------------------------------|
| `00-welcome.png`                      | Welcome page — full viewport showing all three prereq groups (Always required / Use existing / Optional features). |
| `01-tenant-identity.png`              | Step 1 — Engine host dropdown + SPN mode toggle (Create new SecurityInsight Service Principal selected) + cred type + cred storage radios with the Win-host bootstrap callout visible. |
| `02-workspace-ingestion.png`          | Step 2 — Subscription + Region dropdown + workspace name + DCE + storage account fields, all with defaults pre-filled. |
| `03-smtp.png`                         | Step 3 — SMTP card with mode = Anonymous picked + the relay sub-card visible. |
| `04-cmdb.png`                         | Step 4 — CMDB card with mode = CSV picked + the path/refresh sub-card visible. |
| `05-openai.png`                       | Step 5 — Azure OpenAI card with mode = Enabled, Use existing OpenAI resource picked + endpoint/deployment/key fields visible. |
| `06-shodan.png`                       | Step 6 — Shodan card with mode = Enabled + the API key + license tier dropdown visible. |
| `07-output-defender.png`              | Step 7 — JSON sink checkbox + Defender XDR/Sentinel linkage toggle + the "auto-stream Entra logs" sub-card (when no Sentinel) visible. |
| `08-setup-before.png`                 | Step 8 — three phase summary cards + the big **▶ Setup** button + state pill = READY, before any click. |
| `08-setup-success.png`                | Step 8 — same view AFTER a successful Setup: all 3 phase cards green with checkmarks, success banner with AppId / Workspace ResourceId / config path, per-step log panel below. |

**Capture tip:** open the wizard at `http://localhost:8766`, hit `F11` for full-screen browser, use `Win+Shift+S` to grab the page area (no browser chrome). Crop to ~1600×1000 if larger.

Once the PNGs are in this folder, the README image links light up automatically — no further edits needed.
