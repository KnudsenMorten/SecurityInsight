# Setup Wizard — roadmap

The Config Wizard at [`Setup-SecurityInsight.html`](./Setup-SecurityInsight.html) ships today as a **config-file generator** — you fill out the form, the right side renders a `*.custom.ps1` snippet, you copy/paste it into your install.

**Target: end-to-end automation.** Same wizard, but the final *Apply* page actually creates the SPN, applies the permissions, provisions Log Analytics + Storage, and writes `config\SecurityInsight.custom.ps1` for you. No copy/paste. Built incrementally on `main` across the `v2.2.103+` tag range.

---

## Locked spec (what v2.3 will deliver)

### 1. SPN creation

| Input on wizard | Wizard action |
|---|---|
| `SPN display name` (e.g. `sp-securityinsight-myfamily`) | Creates Entra app registration + service principal under that name |
| Cred type radio: **Client secret** or **Self-signed certificate** | Generates the cred automatically |
| Cred storage radio: **Azure Key Vault** *(preferred)*, **Local cert store** *(cert only)*, or **Inline in custom.ps1** *(secret only)* | Stores the cred where the operator picked |

API permissions applied automatically: Microsoft Graph (`ThreatHunting.Read.All`, `Device.Read.All`, `User.Read.All`, `Application.Read.All`, plus the rest of the SI matrix), with admin consent. Azure RBAC: `Reader` at tenant-root MG, `Tag Contributor` for the asset-tagging engine.

### 2. Log Analytics + DCE + DCRs

Creates Workspace, DCE, and the per-engine DCRs in one Resource Group. RBAC `Monitoring Metrics Publisher` granted to the SPN on the DCR resource group.

### 3. Storage account — **RBAC-only, no shared key in the custom file**

The engine has supported OAuth-on-storage since v2.2.79 (auto-detects when `SI_StorageKey` is absent). The wizard takes advantage:

- Creates the Storage Account
- Grants the SPN `Storage Blob Data Contributor` + `Storage Table Data Contributor` + `Storage Queue Data Contributor` on the storage account scope
- **Omits `$global:SI_StorageKey` from the generated config** — works the same for VM-pinned and Container Apps Job hosts

### 4. Custom-file generation

Writes `config\SecurityInsight.custom.ps1` with the **minimum required** for the engines to run:

```
SPN block          : SI_SPN_AppId / Secret-or-Cert / TenantId / ObjectId
Infrastructure     : SI_AzSubscriptionId / SI_Location / SI_PrestageInfra=$true
Workspace          : SI_WorkspaceName / SI_WorkspaceResourceGroup / SI_WorkspaceResourceId
DCE + DCR          : SI_DceName / SI_DceResourceGroup / SI_DcrResourceGroup + per-engine DCR names
Storage            : SI_StorageAccount / SI_StorageResourceGroup       (NO StorageKey)
Output sinks       : SI_Sinks_<Engine> = @('LA','Excel'[,'JSON' if toggled])
RA defaults        : RiskAnalysis_*_Override / AutoBucketCount / OverwriteXlsx
```

### 5. Optional sections — toggled on the wizard

| Toggle | Adds |
|---|---|
| **SMTP** *(optional)* | `SmtpServer / SmtpPort / SMTPUser / SMTPPassword / SMTPFrom / SMTP_UseSSL`, `MailTo`, per-template recipients |
| **Azure OpenAI** *(optional)* | `OpenAI_endpoint / OpenAI_deployment / OpenAI_apiKey / OpenAI_apiVersion`, `BuildSummaryByAI=$true`, `MaxAiSpendPerRun` |
| **JSON output** *(optional)* | Adds `'JSON'` to every `SI_Sinks_<Engine>` |
| **Shodan** *(optional)* | `SI_Shodan_ApiKey` |
| **CMDB CSV** *(optional)* | `SI_EnableCmdbProvider=$true`, `SI_CmdbRefreshIntervalHours`, optional `SI_CmdbCsvPath` |

### 6. Removed from the wizard

- **Power BI deployment** — separate step (run `setup\Deploy-SIPowerBI.ps1` later)
- **Azure Workbook deployment** — separate step (manual import from `docs\Workbook\`)

### 7. Cross-platform host support

The wizard runs on:

- **Windows 11 PC** (non-Azure or Azure)
- **Windows Server** (non-Azure or Azure)
- **VM hosts** and **Azure Container Apps** runtime — same generated `custom.ps1` works for both flavours

For **Azure-hosted runners with a Managed Identity**, the wizard offers a "Use Managed Identity" alternative for storage RBAC instead of an SPN secret/cert (skips the SPN cred entirely, uses the MSI for OAuth-on-storage). Win11 / on-prem servers fall back to SPN cred since MSI isn't available there.

---

## Architecture

| Component | File | Role |
|---|---|---|
| HTML wizard (existing) | `Setup-SecurityInsight.html` | 10-page form, in-browser state, renders config snippets |
| **NEW** PS HttpListener (v2.3) | `Start-SetupWizard.ps1` | Hosts the HTML at `http://localhost:8766`, exposes `/api/*` endpoints the *Apply* page calls |
| Existing scripts (orchestrated, not replaced) | `Bootstrap-Auth.ps1`, `Bootstrap-Storage.ps1` | Endpoints shell out to these — single source of truth for SPN + LA logic |
| **NEW** config writer | `Write-CustomConfig.ps1` | Renders the final `config\SecurityInsight.custom.ps1` from the wizard's collected answers |

---

## Delivery plan (incremental on `main`)

| Tag | Status | Scope |
|---|---|---|
| `v2.2.103` | ✅ shipped | `Start-SetupWizard.ps1` HttpListener skeleton + this ROADMAP + 3-step Quick Start docs |
| `v2.2.104` | ✅ shipped | README cleanup: Quick Start moved under § 4, stale `3.X` labels renumbered to match TOC |
| `v2.2.105` | ✅ shipped | **Backend cmdlets + `/api/apply` orchestration LIVE** — `New-SISpn` (Secret + Cert + MSI; KV / Local / Inline storage), `Initialize-SIInfra` (LA + DCE + Storage with **RBAC-only**, no `SI_StorageKey`), `Write-SICustomConfig` (renders `custom.ps1` from collected state with optional sections). API callable directly via `Invoke-RestMethod` against `http://localhost:8766/api/apply`. |
| `v2.2.106` | ✅ shipped | HTML wizard's Tenant Identity step — **SPN mode toggle** (Create new vs Use existing) + SPN-name field + cred-type radios + cred-storage radios |
| `v2.2.107` | ✅ shipped | HTML wizard's new Apply page (Step 10) — collects state → POSTs to `/api/apply` → renders 3-phase progress (SPN → Infra → Config) with per-phase pending/running/ok/failed status, success summary (AppId / Workspace ID / config path / sections), structured failure UI, and secret-redacted state JSON preview. Plus first-touch default seeding on every `data-default`-bearing input (SPN display name, KV secret name, workspace name + RG, DCE name + RG) so newcomers can click Next without typing, and the SPN-mode toggle now reads "Create new SecurityInsight Service Principal" / "Use existing Service Principal". |
| `v2.2.108` | ⏳ planned | Live log SSE streaming on `/api/log-stream`; drop Power BI + Workbook tabs from HTML |
| `v2.2.109` | ⏳ planned | Smoke-test on lab + 2 customer tenants, polish, README Step 2 rewrite to "fully working" |

---

## Open design notes

- **Log streaming** — the Apply page tails endpoint stdout via Server-Sent Events on `/api/log-stream` so customers see what's happening per phase. Pattern reuses the SI viewer's HttpListener at `viewer/Start-SIViewer.ps1`.
- **Idempotency** — every endpoint is re-runnable. SPN creation: if a SPN with the chosen display name already exists, reuse it (don't create a duplicate); rotate the cred only on operator confirmation.
- **Failure handling** — partial-completion is OK. If LA creation fails after SPN succeeded, the SPN block is still written to `custom.ps1` and the operator can re-run just the LA endpoint.
- **Sample fixtures** — every endpoint ships a `--dry-run` mode that validates the inputs and renders the would-be `custom.ps1` without touching Azure.
