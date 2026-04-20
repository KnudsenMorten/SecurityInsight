# Power BI prerequisites (one-time per tenant)

Step 4 (`Step4_Deploy-SecurityInsight-PowerBI-Dashboard`) and the per-run
`$global:SendToPowerBI` refresh hook in RiskAnalysis both authenticate to
the Power BI REST API using a **service principal**. This doc is the
single place to follow to make that work.

You do this **once per customer tenant**. Takes ~15 minutes.

---

## 1. Create (or reuse) a Power BI SPN

You can reuse the SecurityInsight SPN from Step 2 (`sp-securityinsight`)
if you want one SPN to cover everything. Or create a dedicated SPN
(`sp-securityinsight-powerbi`) if you prefer a narrower blast radius.

In **Entra admin center** → App registrations → New registration:
- Name: `sp-securityinsight-powerbi` (or reuse existing)
- Supported account types: *Accounts in this organizational directory only*
- Redirect URI: (leave empty)
- Click **Register**.

Note the **Application (client) ID** and **Tenant ID** — you'll paste
these into `LauncherConfig.custom.ps1` in step 6.

Under **Certificates & secrets** → New client secret → 24 months →
Copy the value (shown only once).

---

## 2. Grant Power BI API permissions

Still in the Entra admin center, under the app registration:

**API permissions** → Add a permission → **Power BI Service** → *Application permissions* (not Delegated):

- `Tenant.Read.All` — required to list workspaces the SPN can see
- `Workspace.ReadWrite.All` — required to create / update workspaces
- `Dataset.ReadWrite.All` — required to upload + rebind + refresh datasets
- `Report.ReadWrite.All` — required to manage reports

Click **Grant admin consent for <tenant>**.

> **Tenant.Read.All** sometimes isn't visible in the picker. That's OK —
> `Workspace.ReadWrite.All` is the one that actually matters for
> end-to-end deploy; Tenant.Read.All is just a nice-to-have for listing.

---

## 3. Flip the Power BI admin tenant setting

**This is the #1 reason SPN auth fails silently.** Power BI blocks service
principals by default regardless of API permissions.

In the **Power BI admin portal** (https://app.powerbi.com/admin-portal/tenantSettings):

- Find **Developer settings → Allow service principals to use Power BI APIs**.
- Switch to **Enabled**.
- Restrict to a specific security group if your org policy requires it —
  add your Power BI SPN (or a group containing it) to that security group.
- Click **Apply**.

Wait 15 minutes for the setting to propagate (Power BI admin settings
are eventually-consistent).

> While you're in the admin portal, also check **Allow service principals
> to create and use profiles** if you plan to run multiple deployments
> from the same SPN (rare).

---

## 4. Add the SPN as Admin on the target workspace (optional)

Step 4 can **create** the target Power BI workspace if it doesn't exist,
in which case the SPN that created it is automatically the Admin. No
further action needed.

If the workspace **already exists** (e.g. managed by someone else), add
the SPN as **Admin** or at least **Member** on that workspace:

- Open the workspace in the Power BI portal.
- Click **Access** (top-right).
- Paste the SPN's display name (or the app id).
- Role: **Admin**.

---

## 5. Collect the customer's LA Workspace ID

Step 4 writes the **Log Analytics Workspace ID** into the dashboard's
`LA_WorkspaceId` parameter so the KQL queries know where to read from.

This is the **GUID**, not the Resource ID.

In the Azure portal → Log Analytics workspace → Properties → **Workspace ID**.

Copy the GUID. Also note the tenant ID of that workspace (usually the same
tenant as the SPN, but not always — e.g. Lighthouse-managed customers).

---

## 6. Fill in LauncherConfig.custom.ps1

In the SecurityInsight install (`C:\SCRIPTS\SecurityInsight\LAUNCHERS\Step4_Deploy-SecurityInsight-PowerBI-Dashboard\`), copy `LauncherConfig.sample.ps1` to `LauncherConfig.custom.ps1` and populate:

```powershell
# Power BI SPN (from step 1)
$global:Step4_AuthMethod       = 'SpnSecret'
$global:Step4_AuthTenantId     = '<tenant-id-guid>'
$global:Step4_AuthClientId     = '<powerbi-spn-client-id>'
$global:Step4_AuthClientSecret = '<powerbi-spn-secret>'

# LA binding (from step 5)
$global:Step4_LAWorkspaceId    = '<la-workspace-guid>'
$global:Step4_LATenantId       = '<tenant-id-guid>'
```

Or generate this file using the **Setup Configurator → Step 4 — Power BI** tab.

---

## 7. Run Step 4

```powershell
.\LAUNCHERS\Step4_Deploy-SecurityInsight-PowerBI-Dashboard\launcher.community-vm.template.ps1
```

Expected success:

```
[OK] token acquired
[STEP] Resolving Power BI workspace: SecurityInsight-Reports
[APPLIED] created workspace  id=<guid>
[STEP] Uploading SecurityInsight-RiskAnalysis.pbix
[APPLIED] imported  state=Succeeded  reports=1  datasets=1
[APPLIED] parameters rebound
[APPLIED] refresh queued
```

---

## 8. One-time post-deploy step (can't be automated today)

**The Power BI REST API has no supported way to bind OAuth2 credentials
(for the Azure Monitor Logs data source) on an imported dataset.**
Customers must do this one step manually in the Power BI portal:

1. Open `https://app.powerbi.com/groups/<groupId>/settings/datasets/<datasetId>` — the exact URL is printed in the Step 4 summary.
2. **Dataset settings** → if there's a banner about ownership, click **Take over**.
3. **Data source credentials** → next to *Azure Monitor Logs*, click **Edit credentials** → **OAuth2** → **Sign in** → pick an identity that has `Log Analytics Reader` on the target LA workspace.
4. (optional) **Scheduled refresh** → set to match your RiskAnalysis cadence (typically 4x/day or match your cron).

Only needs to be done **once per customer**. After that, every re-run of
Step 4 (dashboard design refresh) preserves the credentials.

---

## 9. Enable per-run refresh from RiskAnalysis (optional)

In the RiskAnalysis engine's `LauncherConfig.custom.ps1`:

```powershell
$global:SendToPowerBI = $true
# Optional overrides -- default to the SPN already used for LA ingest
# $global:PowerBI_WorkspaceName   = 'SecurityInsight-Reports'
# $global:PowerBI_DatasetName     = 'SecurityInsight - Risk Analysis'
# $global:PowerBI_AuthClientId    = '<powerbi-spn-client-id>'
# $global:PowerBI_AuthClientSecret = '<powerbi-spn-secret>'
```

Every RiskAnalysis run now triggers a Power BI dataset refresh at the end
so managers always see the latest data when they open the report.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `API calls to create groups are not allowed` | Admin tenant setting in step 3 not enabled, or SPN not in the allowed security group. |
| `Unauthorized` on POST /groups | Admin consent not granted in step 2. Re-check **API permissions → Grant admin consent**. |
| `403 Forbidden` on dataset refresh | SPN isn't a workspace Admin / Member. Step 4. |
| `Dataset parameters not found` | The `.pbix` doesn't declare the 4 parameters expected by Step 4 (`LA_WorkspaceId`, `LA_TenantId`, `StalenessDays`, `TopNFindings`). Re-author the `.pbix` per `TOOLS/PowerBI/dashboard-spec.md`. |
| Report opens but charts are blank | OAuth2 credentials not bound — do step 8. |
