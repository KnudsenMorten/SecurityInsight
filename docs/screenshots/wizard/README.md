# Setup Wizard screenshots

Drop the following PNGs in this folder (filenames must match exactly — they are referenced from the SI README and from `setup/ConfigWizard/README.md`):

| Filename                       | What to capture                                                                                              |
|--------------------------------|--------------------------------------------------------------------------------------------------------------|
| `01-tenant-identity.png`       | Step 1 page — full viewport showing the **SPN mode** toggle (Create new / Use existing) + the SPN display name input pre-filled with `sp-securityinsight`. |
| `02-workspace-ingestion.png`   | Step 2 page — full viewport showing the workspace name + RG + DCE name + DCE RG inputs all pre-filled with the v2.2 defaults. |
| `10-apply-page.png`            | Step 10 page **before** clicking Apply — three summary cards (SPN / Infra / Config), the big **Apply now** button, the state JSON preview at the bottom (with `***` redactions). |
| `10-apply-success.png`         | Step 10 page **after** a successful apply — all three phase cards green with checkmarks, the success banner with AppId / Workspace ID / config-file path. |

Suggested capture: open the wizard at `http://localhost:8766`, hit `F11` for full screen, use Snipping Tool / `Win+Shift+S` to grab the page area (no browser chrome). Crop to ~1600×1000 if larger.

Once the four PNGs are in this folder, the README image links light up automatically — no further edits needed.
