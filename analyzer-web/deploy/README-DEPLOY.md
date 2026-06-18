# SI Analyzer (SIA) — hosting & deploy (internal env)

Hosted, executive-grade SecurityInsight Analyzer. **Azure Container Apps** (private
ingress + Managed Identity) in the **internal env** by default. App Service *for
Containers* also works; the same image + env vars apply. The agent that built this does
**not** deploy — the **main session** (which holds Azure creds) runs the commands below.

> This file is PUBLIC (it ships in the per-solution mirror). It MUST stay placeholder-only:
> never put the real workspace customerId / resource id / subscription / RG / tenant /
> app-registration ids here. Those live ONLY in the internal, stripped
> `internal/ENGINE-IDENTITY.md` — copy the exact values from there when you run the command.

## What the app needs at runtime
- **Data plane** — `Sia__WorkspaceId` = the internal SI Log Analytics workspace
  **customerId (GUID)**, queried **READ-ONLY** via the app's **Managed Identity** (granted
  **Log Analytics Reader** on the workspace resource id). The scored findings come from the
  RA output table `SI_RiskAnalysis_Summary_CL` (the worklist/exec rollup) — not the
  attribute-only `SI_*_Profile_CL` tables — using the latest-snapshot pattern
  (`where CollectionTime == toscalar(... | summarize max(CollectionTime))`). This is the
  default base.
- **AI (on by default)** — `Sia__OpenAiEndpoint` + `Sia__OpenAiDeployment` = the SI
  Azure OpenAI deployment. The MI (or a key) authenticates; grounded + fail-soft.
- **Auth** — **Entra / Easy Auth** in front of the app (a hosted analyzer of security
  findings is never anonymous).
- Leave `Sia__WorkspaceId` empty (or set `Sia__UseDemoData=true`) for the demo fallback.
- **Scheduled exec-summary email (optional, fail-soft)** — the app can email the grounded
  exec summary on a cadence "so the CIO gets it without opening the tool". It is **OFF until
  configured** and **never crashes** when half-configured (it renders but does not send). Set
  via the `Sia__Email__*` app settings (the SMTP secrets are Key-Vault-backed app settings):
  - `Sia__Email__Enabled` = `true` to turn the scheduler on.
  - `Sia__Email__Recipients__0`, `__1`, … = the To addresses (no recipients ⇒ no send).
  - `Sia__Email__Cadence` = `daily` | `weekly` | `monthly` (default `monthly`); `Sia__Email__SendAtHour` = 0–23 (host local).
  - `Sia__Email__Period` = `previous` | `month` | `quarter` | `half` | `year` (figures snap to this; default quarter).
  - `Sia__Email__BaseUrl` = the app's public base URL (e.g. `https://<app>...`) ⇒ the email links to `{BaseUrl}/board` (omit ⇒ no link).
  - `Sia__Email__OrgLabel` = a friendly org label for the subject (optional; never a tenant id).
  - `Sia__Email__SmtpHost` / `__SmtpPort` (default 587) / `__SmtpUseSsl` (default true) / `__SmtpUser` / `__SmtpPassword` / `__FromAddress` = the SMTP transport (operator-completed; host + from required to actually send).
  - Verify without waiting for the cadence: `GET /api/email/preview` (renders the email HTML, no send) and `POST /api/email/send` (manual "send now"; returns a JSON `{sent, recipientCount, detail}` result). The transport is swappable for a Graph sender without code changes to the orchestration.

## 1. One command does build + deploy + MI grant + Easy Auth
`Deploy-SiaAnalyzer.ps1` now finalizes the whole runtime: it builds + deploys the image,
ensures the system-assigned MI, grants it **Log Analytics Reader** (read-only) on the
workspace, optionally grants **Cognitive Services OpenAI User** on the AOAI account, and
configures Entra Easy Auth.

```powershell
# from SOLUTIONS/SecurityInsight/analyzer-web
# (fill EVERY <...> from internal/ENGINE-IDENTITY.md — do NOT commit real ids into this file)
.\deploy\Deploy-SiaAnalyzer.ps1 `
    -ResourceGroup rg-securityinsight `
    -AcrName <acr-name> `
    -AppName sia-analyzer `
    -WorkspaceId <workspace-customerId-guid> `
    -WorkspaceResourceId "/subscriptions/<sub>/resourceGroups/rg-securityinsight/providers/Microsoft.OperationalInsights/workspaces/log-platform-management-securityinsight" `
    -OpenAiEndpoint https://<aoai-name>.openai.azure.com `
    -OpenAiDeployment <deployment-name> `
    -OpenAiAccountId "/subscriptions/<sub>/resourceGroups/<aoai-rg>/providers/Microsoft.CognitiveServices/accounts/<aoai-name>" `
    -AuthClientId <app-registration-client-id> `
    -AuthTenantId <tenant-id>
```
- `-WorkspaceId` is the **customerId GUID** the SDK queries; `-WorkspaceResourceId` is the
  **ARM resource id** of the same workspace used as the role-grant scope (both required).
- Omit `-OpenAiAccountId` if AOAI uses a key (set `Sia__OpenAiApiKey` as a secret env var instead of MI).
- Use `-SkipGrant` / `-SkipAuth` to run those steps by hand (sections 2–3 below).
- The script prints the URL + `/health` + the live-verify checklist.

## 2. Manual MI → Log Analytics Reader (only if you used -SkipGrant)
```powershell
az containerapp identity assign -g rg-securityinsight -n sia-analyzer --system-assigned
$pid = az containerapp identity show -g rg-securityinsight -n sia-analyzer --query principalId -o tsv
az role assignment create `
    --assignee-object-id $pid --assignee-principal-type ServicePrincipal `
    --role "Log Analytics Reader" `
    --scope "/subscriptions/<sub>/resourceGroups/rg-securityinsight/providers/Microsoft.OperationalInsights/workspaces/log-platform-management-securityinsight"
# If Azure OpenAI uses MI (no key), also:
az role assignment create --assignee-object-id $pid --assignee-principal-type ServicePrincipal `
    --role "Cognitive Services OpenAI User" `
    --scope "/subscriptions/<sub>/resourceGroups/<aoai-rg>/providers/Microsoft.CognitiveServices/accounts/<aoai-name>"
```

## 3. Manual Easy Auth (Entra) (only if you used -SkipAuth)
```powershell
az containerapp auth microsoft update -g rg-securityinsight -n sia-analyzer `
    --client-id <app-registration-client-id> `
    --issuer https://login.microsoftonline.com/<tenant-id>/v2.0
az containerapp auth update -g rg-securityinsight -n sia-analyzer `
    --unauthenticated-client-action RedirectToLoginPage --redirect-provider azureactivedirectory
```
(Register an Entra app for the Analyzer; restrict sign-in to the appropriate group.)

## 4. Verify (live release gate — main session)
- Open `https://<fqdn>/` → must land on the **executive** view (redirect to `/exec`).
- Sign in with Entra (Easy Auth).
- Confirm live data (banner shows "Live data") + an AI-written exec summary (banner
  "AI narrative on"), grounded in real RA findings from `SI_RiskAnalysis_Summary_CL`.
- `/analyst` prompt + a guarded KQL run; a write attempt is rejected.
- `POST /mcp` `tools/list` returns the read-only tool catalogue.

Until this hosted run passes (real internal workspace + AI-on + Entra sign-in), SIA stays
in REQUIREMENTS.md (not FEATURES.md) — the hosted live-verify is the release gate.
