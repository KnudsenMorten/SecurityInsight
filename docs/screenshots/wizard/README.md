# Setup Wizard screenshots

Referenced from the SI README §4 and `setup/ConfigWizard/README.md`. Filenames must stay as they are.

| Filename | What it shows |
|---|---|
| `SetupWizard-0-Start.png` | Starting the wizard from PowerShell |
| `SetupWizard-0-Start-Error-Connect.png` | The pre-flight refusing to start without the Az / Graph / az CLI sign-ins, and the commands it prints |
| `SetupWizard-0-WelcomeWizard.png`, `Setup-wizard.png` | Welcome page — what to have ready, grouped by when it is needed |
| `SetupWizard-1-ConnectMethods.png` | Step 1 — engine host and service-principal mode |
| `SetupWizard-1-ConnectMethods-SPN.png` | Step 1 — tenant + SPN name, credential, the asset-tagging opt-in, generated snippet |
| `SetupWizard-2-Workspace-ingestion.png` | Step 2 — subscription, region, workspace, DCE, storage |
| `SetupWizard-3-Mail.png` | Step 3 — mail via an anonymous relay |
| `SetupWizard-4-CMDB.png` | Step 4 — CMDB from a CSV file |
| `SetupWizard-5-OpenAI-integration.png` | Step 5 — Azure OpenAI enabled, existing resource |
| `SetupWizard-6-Shodan-integration.png` | Step 6 — Shodan enabled |
| `SetupWizard-7-Json-defender-integration.png` | Step 7 — JSON sink, Defender XDR workspace linkage, Entra sign-in log streaming |
| `SetupWizard-7-DiagnosticsLogs.png` | Step 7 — the Entra diagnostic-setting categories and cost note |
| `SetupWizard-8-Setup.png` | Step 8 — review: what each setup phase will do, before **Setup Infrastructure** is clicked |

The browser pages are captured headlessly at 2000×1150 from a running wizard (`Start-SetupWizard.ps1 -NoBrowser`); Setup is never clicked during a capture.
