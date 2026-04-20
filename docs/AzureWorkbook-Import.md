# Azure Workbook — import guide

The `TOOLS/AzureWorkbook/SecurityInsight-RiskAnalysis.workbook.json` file is a
ready-to-import Azure Monitor Workbook. Two paths to land it on a customer's
Log Analytics workspace.

---

## Option A — Portal import (fastest)

1. Open the Azure Portal → **Azure Monitor** → **Workbooks**.
2. Click **+ New**.
3. In the empty workbook, click **</>** (Advanced Editor) in the toolbar.
4. Template type **Gallery Template** is fine for this format.
5. **Paste** the contents of `SecurityInsight-RiskAnalysis.workbook.json` into
   the editor, replacing whatever's there.
6. Click **Apply**.
7. In the first tile's parameter pills, pick the time range + the LA workspace
   (the workbook binds to whichever workspace context you're viewing it from).
8. **Save** → give it a name (e.g. *SecurityInsight — Risk Analysis*) and save
   to the customer's shared workbooks.

Takes about 60 seconds.

---

## Option B — ARM template (scripted / CI)

Wrap the workbook JSON inside a standard Azure `Microsoft.Insights/workbooks`
ARM resource and deploy via `New-AzResourceGroupDeployment`. Template:

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "workbookDisplayName": {
      "type": "string",
      "defaultValue": "SecurityInsight -- Risk Analysis"
    },
    "workbookSourceId": {
      "type": "string",
      "metadata": { "description": "Resource ID of the LA workspace the workbook reads from." }
    }
  },
  "resources": [
    {
      "type": "microsoft.insights/workbooks",
      "name": "[guid(parameters('workbookDisplayName'))]",
      "apiVersion": "2022-04-01",
      "location": "[resourceGroup().location]",
      "kind": "shared",
      "properties": {
        "displayName":    "[parameters('workbookDisplayName')]",
        "serializedData": "[string(<PASTE_WORKBOOK_JSON_HERE>)]",
        "sourceId":       "[parameters('workbookSourceId')]",
        "category":       "workbook"
      }
    }
  ]
}
```

The `serializedData` field takes the workbook JSON as a **string**. Two ways
to deploy:

**PowerShell one-liner** (reads + escapes the JSON, calls ARM):

```powershell
$workbook = Get-Content `
    'C:\SCRIPTS\SecurityInsight\TOOLS\AzureWorkbook\SecurityInsight-RiskAnalysis.workbook.json' -Raw
$serialized = $workbook -replace '"','\"'   # string-ify for ARM
# Then either inline it in a template and deploy, or create the resource directly:
New-AzOperationalInsightsWorkspaceWorkbook `
    -ResourceGroupName 'rg-securityinsight' `
    -DisplayName       'SecurityInsight -- Risk Analysis' `
    -Location          'westeurope' `
    -SerializedData    $workbook `
    -SourceId          '/subscriptions/.../workspaces/log-securityinsight'
```

> If you don't have `Az.ApplicationInsights` or equivalent, use the REST API
> directly: `PUT /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Insights/workbooks/<guid>?api-version=2022-04-01`.

---

## Filters available in the workbook

Every tile respects the filter pills at the top of the workbook. Parameters:

| Parameter | Type | Default | Drives |
|---|---|---|---|
| `Workspace` | **Resource picker** (LA workspace) | (prompt on first open) | Every query's `crossComponentResources` — no per-tile workspace picker. |
| `TimeRange` | Built-in time range | Last 30 days | `where TimeGenerated in TimeRange` on every query |
| `LatestRunOnly` | Dropdown (Yes/No) | Yes | KPIs + Top-N respect only `max(CollectionTime)` when Yes |
| `SecurityDomain` | Multi-select dropdown | `*` (all) | `where '*' in ({SecurityDomain}) or SecurityDomain in ({SecurityDomain})` |
| `SecuritySeverity` | Multi-select dropdown | `*` (all) | Same `'*' in ...` sentinel pattern |
| `CriticalityTier` | Multi-select dropdown | `*` (all) | Same |
| `SubCategory` | Multi-select dropdown | `*` (all) | Same |
| `SearchText` | Free text | (empty) | `contains` match on `ConfigurationName` + `TraceName` |
| `TopN` | Free text (number) | 25 | Size of the Top-N table |

**How "All" works:** every multi-select dropdown's query prepends a hard-coded
`*` value to the dynamic list, and every KQL filter is written as:

```
| where '*' in ({Param}) or Column in ({Param})
```

So selecting `*` alone skips the filter entirely (both KPIs and drill-downs
still return rows). Deselecting `*` and ticking specific values applies the
normal `in (...)` filter. This pattern avoids the "empty expansion" parse
error you get when a `value::all` sentinel expands to nothing.

**Workspace chaining:** every query (including the dropdown-population queries)
is bound to `{Workspace}` via `crossComponentResources`. Pick the workspace
once at the top — never get prompted again per tile.

Filter chaining: every dropdown query also filters by `TimeRange`, so changing
the time range automatically updates what values show up in the pills.

---

## Tiles laid out

1. **Header** — title + data-sources blurb.
2. **Filter pills** — parameters block (see above).
3. **KPI tiles** — 4 big numbers: Total risk score, Open findings, Critical findings, Δ % vs previous run.
4. **Trends row** — three charts side-by-side:
   - Total risk score + open findings over time (line).
   - Risk by `SecurityDomain` over time (stacked area).
   - Risk by `CriticalityTier` over time (stacked area).
5. **Velocity** — new vs resolved `TraceID`s per run (grouped bar).
6. **Top-N table** — ranked findings on the latest (or full range) run, filterable by the pills.
7. **Stale findings** — `TraceID`s that appear in ≥2 runs and are still open on the latest run, sorted by `DaysOpen`.
8. **Identity inventory** — latest collection from `SI_IdentityAssets_CL` with column-level filter enabled.

---

## Customising the workbook

Edit the file directly — the JSON is hand-authorable. Common tweaks:

- **Add a new filter pill**: copy any `p-domain` / `p-severity` parameter block and change the `query` + the field name.
- **Add a new tile**: copy any `"type": 3` block at the bottom, change the `query` + `visualization`, put it below the existing tiles.
- **Change colours**: every grid has a `formatters` array — adjust `palette` (`redGreen`, `orange`, `blue`, `purple`, ...).
- **Embed in another workbook**: use a `"type": 12` link item that points at this workbook's resource ID.

After edits: validate with `Get-Content ... | ConvertFrom-Json` in PowerShell,
then re-import via Option A.
