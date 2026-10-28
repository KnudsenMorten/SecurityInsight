# Testing with the SecurityInsight test pack

Your team can build and approve the integration before SecurityInsight runs against your instance. On **Configuration >
Connectors > Setup**, open a connector of kind **servicenow** or **sql**. The section **Sample data for your ServiceNow
team** shows example rows on fictional demo data for every object of the hand-off database and of the ServiceNow push,
with every column explained. **Download test pack (zip)** gives:

| File | What it is |
|---|---|
| `sql/vImportBatch.csv`, `sql/vImportCi.csv`, `sql/vImportCiKeyValue.csv`, `sql/vImportCiRelation.csv`, `sql/vProposedCi.csv`, `sql/vImportVulnerableItem.csv` | One CSV per view, as a JDBC data source reads it (the columns of a hand-off database of your own) |
| `rest/u_si_ci_import.insertMultiple.json`, `rest/u_si_vuln_import.insertMultiple.json` | The request bodies of the ServiceNow push: every row with `u_action`, `u_row_hash`, `u_si_batch_id`, `u_si_cleared`, `u_si_reason`, `u_si_replaces` and `u_source_run` |
| `rest/u_si_staging_status.json` | The staging status rows of a complete, a failed and a held batch, each `writing` first |
| `columns.csv` | Every column of every object: type, always or when known, meaning, ServiceNow field, example |
| `servicenow-test-pack.json` | Everything above in one file, with the case of every row |
| `HOW-TO-TEST.md` | The steps, the cases with the result to expect, and the approval checklist |

**Preview with your data** (Admin) shows the first rows of your own hand-off views, read only. For the push, use
**ServiceNow team pack (Excel)** and **ServiceNow schema (JSON)** on *Configuration > Connectors > Fields sent*: real
rows with the columns in force, and the schema to create the tables from. The same pages count the rows each output
would send and export every one of them as Excel or CSV.

To test in a developer or sub-production instance:

1. Register the discovery source, create the staging tables, the staging status table and the REST Insert Multiple
   records, and add the identification and reconciliation rules (see
   [Setting up ServiceNow for SecurityInsight](servicenow-setup)).
2. Load the CSV files into the import set tables (*System Import Sets > Load Data*), or post the `rest/` bodies:
   `POST /api/now/import/<table>/insertMultiple` for the data rows, one row per `POST /api/now/import/u_si_staging_status`
   for the status rows.
3. Run your transforms and compare each case with the result `HOW-TO-TEST.md` expects: CIs that are new, changed,
   unchanged, unmatched, asset-keyed, not-seen and retired, an identity; removed tags and relations; vulnerable items
   opened, still reported, reopened, held and closed as Remediated, Out of scope, AssetRetired and Duplicate, a Defender
   for Cloud recommendation, an identity finding; and a complete, a failed and a held batch.
4. Check the push rules on the `rest/` rows: an `update` row with an unchanged `u_row_hash` is skipped, a `held` row
   changes nothing, the columns in `u_si_cleared` are cleared and no other empty column is, and a batch is imported only
   after its `complete` row.
5. Work through the approval checklist in `HOW-TO-TEST.md`.
6. Connect the real feed: the JDBC data sources, or the three table names on the data-out connector. Then ask your
   SecurityInsight admin for a test batch (**Send a test batch...** on the card *ServiceNow: one route*): at most 5 real
   rows per output, mode `test`, which your importer must skip.

What each case should do in ServiceNow is on [Handling records and states](servicenow-records-and-states).

Verified against SecurityInsight 3.0.0.202610261957 on 2026-10-27.
