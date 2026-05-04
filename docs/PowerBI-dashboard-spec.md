# SecurityInsight — Power BI dashboard blueprint

This document describes the `.pbix` you build **once** in Power BI Desktop.
Follow it step-by-step; once saved, the Step 4 launcher deploys the same
`.pbix` to every customer's Power BI tenant fully automatically.

---

## Parameters (set at `.pbix` open time)

Customers get prompted for these on first open. The Step 4 launcher patches
them via the REST API on upload.

| Parameter name        | Type        | Example                                          |
|-----------------------|-------------|--------------------------------------------------|
| `LA_WorkspaceId`      | Text        | `abc12345-6789-...-000000000000` (LA Workspace ID, GUID only — not the Resource ID) |
| `LA_TenantId`         | Text        | `fedcba98-7654-...-000000000000` |
| `StalenessDays`       | Decimal nbr | `30` |
| `TopNFindings`        | Decimal nbr | `25` |

In Power BI Desktop:

1. **Transform data → Manage parameters → New Parameter** for each.
2. For every KQL query, `Home → Advanced Editor → ` replace the hard-coded
   workspace GUID with `Source = AzureDataExplorer.Contents("https://ade.loganalytics.io/subscriptions/.../workspaces/" & LA_WorkspaceId, ...)` — or use the Azure Monitor Logs connector and set the workspace via the parameter.

---

## Data model

Eight queries, all powered by KQL against the customer's LA workspace:

| Table name          | KQL file                                   | Grain                         |
|---------------------|--------------------------------------------|-------------------------------|
| `RiskSummary`       | `queries/01-RiskAnalysis-Summary-LatestRun.kql`          | One row per TraceID at latest CollectionTime |
| `RiskSummaryTrend`  | `queries/02-RiskAnalysis-Summary-Trend.kql`              | One row per (CollectionTime, TraceID) |
| `NewVsResolved`     | `queries/03-RiskAnalysis-NewVsResolved-PerRun.kql`       | One row per CollectionTime |
| `TopN`              | `queries/04-RiskAnalysis-TopN-CurrentRun.kql`            | One row per TraceID (top-N only) |
| `Stale`             | `queries/05-RiskAnalysis-StaleFindings.kql`              | One row per TraceID (long-open) |
| `TenantTrend`       | `queries/06-RiskAnalysis-RiskScoreTrend-Aggregated.kql`  | One row per CollectionTime |
| `DomainTrend`       | `queries/07-RiskAnalysis-BySecurityDomain-Trend.kql`     | One row per (CollectionTime, SecurityDomain) |
| `IdentityLatest`    | `queries/08-IdentityAssets-LatestCollection.kql`         | One row per identity (latest collection) |

Load all eight as separate queries. No relationships are strictly required —
each table answers a different question. Optional: relate `RiskSummary[TraceID]` → `Stale[TraceID]` and `RiskSummary[TraceID]` → `RiskSummaryTrend[TraceID]` for drill-through.

---

## Measures

Paste every line from `measures.dax` into **Modeling → New measure**.

Key ones to expose on the canvas:

- `Total Risk Score (Latest)`
- `Risk Score Delta % vs Prev Run`
- `Open Findings (Latest)`
- `Critical Findings (Latest)`
- `New Findings (Latest Run)` / `Resolved Findings (Latest Run)` / `Net Finding Movement`

---

## Page layout

Three pages. Design for a 16:9 exec deck (1920x1080) so screenshots look good.

### Page 1 — Executive summary

```
+----------------------------------------------------------------------------------+
|  SecurityInsight — Risk Overview                        Last run: {CollectionTime}|
+----------------------------------------------------------------------------------+
| [ Total Risk  ] [ Open         ] [ Critical     ] [ Δ vs prev    ]              |
| [   Score     ] [ Findings     ] [ Findings     ] [ run (%)      ]              |
| [   1,234     ] [   87         ] [   12         ] [   -8.4%  ↓   ]              |
+----------------------------------------------------------------------------------+
|                                                                                  |
|     Total risk score over time (line chart, TenantTrend[CollectionTime] vs      |
|     TenantTrend[TotalRiskScore])                                                |
|                                                                                  |
+----------------------------------------------------------------------------------+
|  Risk by SecurityDomain over time (stacked area, DomainTrend)                   |
+----------------------------------------------------------------------------------+
```

**Cards**: `Total Risk Score (Latest)`, `Open Findings (Latest)`,
`Critical Findings (Latest)`, `Risk Score Delta % vs Prev Run`.

**Line chart**: X = `TenantTrend[CollectionTime]`, Y = `TenantTrend[TotalRiskScore]`.

**Stacked area**: X = `DomainTrend[CollectionTime]`, Y = `DomainTrend[DomainRiskScore]`, Legend = `DomainTrend[SecurityDomain]`.

### Page 2 — Top findings (operational)

```
+----------------------------------------------------------------------------------+
| Slicer: SecurityDomain / SecuritySeverity / CriticalityTier                     |
+----------------------------------------------------------------------------------+
|                                                                                  |
|     Top 25 findings by risk score (table, TopN)                                 |
|     Columns: TraceName | Severity | Tier | RiskScore | Assets | Issues         |
|                                                                                  |
+----------------------------------------------------------------------------------+
|     Velocity (combo chart, NewVsResolved)                                       |
|     Bars = New (green) / Resolved (blue) per CollectionTime                     |
|     Line  = Net movement                                                         |
+----------------------------------------------------------------------------------+
```

### Page 3 — Stale findings (chase list)

```
+----------------------------------------------------------------------------------+
|  Findings open for 30+ days (table, Stale sorted by DaysOpen desc)              |
|  Columns: TraceName | Config | Severity | FirstSeen | DaysOpen | MaxRiskScore   |
|                                                                                  |
|  Click a row → drill-through to RiskSummaryTrend filtered by TraceID            |
+----------------------------------------------------------------------------------+
|  Drill-through page: line of RiskScoreTotal vs CollectionTime for the clicked   |
|  TraceID. Shows the history of ONE finding over time.                           |
+----------------------------------------------------------------------------------+
```

---

## Colour + formatting

- **Severity palette** (use a calculation group or conditional formatting on `SecuritySeverity`):
  - `Very High` / `Critical` → `#A83275` (danger pink)
  - `High` → `#E57373` (muted red)
  - `Medium` → `#B07A00` (amber)
  - `Low` → `#1A7A1A` (green)
- **CriticalityTier palette**:
  - `Tier 0` → `#0D1117` (near-black)
  - `Tier 1` → `#2A6592` (accent blue)
  - `Tier 2` → `#656D76` (muted grey)
- Dates formatted `yyyy-MM-dd HH:mm UTC` so customers can't misinterpret timezones.

---

## Save → ship

1. **File → Save as → `SecurityInsight-RiskAnalysis.pbix`** in
   `SOLUTIONS\SecurityInsight\TOOLS\PowerBI\`.
2. **File → Export → Power BI template (`.pbit`)** to the same folder.
3. Commit both to the monorepo. The Step 4 launcher uploads the `.pbix`; the `.pbit` is the "customer-edits-a-copy" artefact for offline tinkering.

That's the one-time Desktop work. Once the `.pbix` is in the monorepo, every
new customer onboarding just runs Step 4 and the dashboard lands in their
Power BI tenant automatically.
