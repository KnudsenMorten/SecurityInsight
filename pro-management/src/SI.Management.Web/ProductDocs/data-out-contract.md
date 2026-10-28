# The SecurityInsight data contract

SecurityInsight hands its data to other systems under **one contract**: the same keys, the same values, the same batch
states and the same rule for when a reader may act. This page is the contract. It applies to every data-out target:

| Target | What it carries | Where the batch state is | Batch id on the rows |
|---|---|---|---|
| **ServiceNow push** (the ServiceNow data-out connector) | CIs and vulnerable items, posted to your Import Set staging tables | The staging status table (`u_si_staging_status`) | `u_si_batch_id` on every row |
| **Hand-off database, the Pro database** (your MID Server reads SQL views) | CIs, tags, relations, proposed CIs, vulnerable items | `snowstage.vImportBatch` (the batches of the CI hand-off and of the two SQL connectors below) | `u_si_batch_id` on `snowstage.vImportCi` and `snowstage.vImportVulnerableItem` |
| **Hand-off database of your own** (a connector of kind **sql**, direction **cmdb**) | CIs, tags, relations, proposed CIs | Its own `snowstage.vImportBatch` (`u_si_batch_id`, `u_state`) | `u_si_batch_id` (and the older `u_batch_id`, the same value) on every row |
| **CMDB SQL connector** | SecurityInsight's CI table `cmdbsync.ConfigurationItem` | `cmdbsync.SyncRun` | `SiBatchId` on each CI it wrote |
| **SQL vulnerability connector** | `vuln.VulnerabilityItem` | `vuln.SyncRun` | `SiBatchId` on each record, from the write itself |

The ServiceNow pages describe the ServiceNow side in detail: [ServiceNow integration overview](servicenow-overview),
[ServiceNow staging tables and columns](servicenow-columns), [Handling records and states](servicenow-records-and-states)
and [Knowing when a sync is complete](servicenow-sync-complete).

## The rule

> **Act only on rows of a complete batch.** A batch is `writing` while SecurityInsight writes it, then `complete`,
> `failed` or `held`. Import a `complete` batch once; never import a `writing`, `failed` or `held` batch, and never a
> batch in mode `test`.

| Batch state | What it means | What a reader does |
|---|---|---|
| `writing` | SecurityInsight is writing the batch | Wait |
| `complete` | Every row of the batch was accepted | Import it, once, oldest first |
| `failed` | Some rows were not accepted, or the batch never ended | Do not import. Its rows come again in a later batch |
| `held` | SecurityInsight stopped the batch before or while writing, by a check | Do not import. What you imported before stays |
| `feedback` (ServiceNow push only) | Information: the import result SecurityInsight read back for a complete batch | Not a batch state. Ignore it for the import |

```text
                     +--> complete   import it, once
                     |
   writing  ---------+--> failed     do not import; the rows go again
                     |
                     +--> held       do not import; nothing changes
```

Each batch moves one way. A batch id never comes back. There is never more than one `writing` batch per output: when a
sync starts and finds a batch of the same output still `writing`, it ends that batch as `failed` with the reason *a
later sync started while this batch was still writing*, and the rows of that batch go again in the new one.

How each target makes a batch:

| Target | Batch id | How `complete` is set |
|---|---|---|
| ServiceNow push | `<run id>:<output>` | A second row in the staging status table, after the last data row |
| CMDB SQL connector | `<run id>:cmdb-sql` | In the **same transaction** as the CI changes. A reader never sees a CI change without the `complete` row |
| CI hand-off, the Pro database | `<run id>:cmdb-handoff` | After the last CI row of the run is written. The batch is `writing` from before the first row, and every CI row it writes carries its id from that write on. An error ends it `failed` |
| SQL vulnerability connector | `<run id>:vuln-sql:<connector>` | At the end of the run. The connector writes **record by record, not in one transaction**, so a reader can see a run's records while its batch is still `writing`. Every record the run writes carries the run's batch id **from that write on** (the batch row is written first, so the id is always one you can look up), and the batch end adds the clear marker. A record whose `u_si_batch_id` names a `writing` or `failed` batch is not to be acted on yet |
| Hand-off database of your own | the run | One statement after the row count is checked. The import views show only the newest complete batch |

`snowstage.vImportBatch` in SecurityInsight's own database lists the batches of the CI hand-off and of both SQL connectors,
with the same words as the staging status table: `u_si_batch_id`, `u_output` (`servicenow-ci` for the CI hand-off
(`u_connector` = `cmdb-handoff`) and the CMDB SQL connector,
`servicenow-vulnerable-item` for the SQL vulnerability connector), `u_state`, `u_started_at`, `u_finished_at`,
`u_batch_time`, `u_reason`, `u_si_contract_version`, `u_si_mode`, the counts per action and `u_landed_rows`.

**The reader rule for the SQL vulnerability connector:** read `snowstage.vImportVulnerableItem`, and act on a row only
when its `u_si_batch_id` is a `complete` batch in `snowstage.vImportBatch`. Skip the other rows; the next complete batch
carries them. A record the newest run did not write keeps the id of the batch that last wrote it, which is complete.

**The reader rule for the Pro database's CI views** (`snowstage.vImportCi`) is the same: act on a row only when its
`u_si_batch_id` is a `complete` batch in `snowstage.vImportBatch`. Each run writes the views as one batch of its own,
`<run id>:cmdb-handoff`: while it writes, the rows it has written carry that batch's id and the batch is `writing`, so
you skip them; the rows it has not reached yet still carry the id of the complete batch before. A row the newest run did
not write keeps the id of the complete batch that last wrote it.

## The contract version

Every batch carries `u_si_contract_version` (SQL: `ContractVersion`). The version is **`1`**.

The rule for a version: **columns and values are only ever added.** Renaming or removing a column, or changing what a
value means, comes with a new contract version. A reader that checks the version and ignores columns it does not know
keeps working when a column is added.

## Keys

| Record | Key | Notes |
|---|---|---|
| CI | `u_si_correlation_id` | One stable key per CI. An opaque text of up to 400 characters |
| Vulnerable item | `u_si_correlation_id` + `u_vulnerability` | The CI key and the finding key |
| Vulnerable item, stable id | `u_source_record_id` | ServiceNow push: `<CI key>|<finding key>`. Hand-off database: the record's GUID. Both never change for one finding on one CI |
| Tag | `u_si_correlation_id` + `u_source` + `u_key` | Hand-off database only |
| Relation | `u_parent_correlation_id` + `u_child_object_id` + `u_relation_type` | Hand-off database only |

Coalesce on the key. A row sent twice then updates the same record and never makes a second one.

## The columns on every pushed row

Every row of both ServiceNow push outputs carries these columns, whatever else an admin changes in the output's columns:

| Column | Meaning |
|---|---|
| `u_action` | What the row asks for: `new`, `update`, `close`, `reopen`, `held` or `out_of_scope` (below) |
| `u_row_hash` | A SHA-256 fingerprint of the row's **content** columns. The action, the batch, the clear marker, the reason, the replaced key and the run columns (`u_source_run`, `u_run_time`, `u_changed_at`) are not part of it. An unchanged record arrives as `update` with the same hash |
| `u_si_batch_id` | The batch that delivered the row, `<run id>:<output>` |
| `u_si_cleared` | The clear marker: the clearable columns that are empty now, comma separated (below) |
| `u_si_reason` | Why the row is `held` or `out_of_scope`, in plain words; empty otherwise |
| `u_si_replaces` | The key this record replaces after a re-key (below); empty otherwise |
| `u_source_run` | The SecurityInsight run the values come from. A `held` row keeps the run of its last values |

## The columns on every database row

The hand-off databases carry the same contract on their import views. Each column is added after the columns a view
already had, so an existing data source and transform map keep reading what they read before:

| View | Contract columns |
|---|---|
| `snowstage.vImportCi` (both hand-off databases) | `u_si_batch_id`, `u_action`, `u_si_cleared`, next to `u_row_hash` and `u_source_run` |
| `snowstage.vImportVulnerableItem` | `u_si_batch_id`, `u_action`, `u_si_cleared` |
| `snowstage.vImportBatch`, `snowstage.vImportCiKeyValue`, `snowstage.vImportCiRelation` (hand-off database of your own) | `u_si_batch_id` (the same value as `u_batch_id`, which stays) |

`u_action` on a database row is the record's action in the batch that last wrote it:

| Record | `u_action` |
|---|---|
| CI | `new` when that batch added it, `close` when it is retired, `reopen` when a retired CI is seen again, `update` otherwise |
| Vulnerable item | `new` when that batch opened it, `reopen` when it reopened it, `close` when it is closed, `out_of_scope` when it closed as *Out of scope*, `held` while its absence is being counted (`u_absent_runs` above 0), `update` otherwise |

`u_si_cleared` follows the same rule as on a pushed row (below), over the same clearable columns. A held vulnerable item
carries no clear marker.

## Every sync sends the full state

Every sync of a ServiceNow push output sends the **full current scoped state** of that output, as one batch: every CI in
scope, every vulnerable item in scope, open and closed, each with its `u_action`. The CI output runs before the vulnerable
item output.

The action of each record comes from what the record is in SecurityInsight now, and what your instance last received
for it in a **complete** batch (the *base*):

| Now in SecurityInsight | Base: none | Base: open or active | Base: closed or retired | Base: out of scope, or gone |
|---|---|---|---|---|
| CI active or not-seen; vulnerable item open | `new` | `update` | `reopen` | `reopen` |
| CI retired; vulnerable item closed | `close` | `close` | `close` | `close` |
| Vulnerable item open, absence still counting (`u_absent_runs` above 0) | `new` | `held` | `reopen` | `reopen` |
| Out of the output's scope | no row | `out_of_scope`, once | no row | no row |
| Left out this run: a disabled account or device, a report that could not complete, or (vulnerable item) its CI not delivered | no row | `held`, last values | `held`, last values | no row |
| No longer in SecurityInsight's data | no row | `held` once, then no row | `held` once, then no row | no row |

| `u_action` | What the reader does |
|---|---|
| `new` | Create the record, or update it if it exists |
| `update` | Update the record. Skip it when `u_row_hash` equals the hash you keep |
| `close` | Close the record with `u_close_reason`. Already closed, or never created: nothing |
| `reopen` | Reopen the record |
| `held` | **Change nothing.** SecurityInsight cannot confirm or close the record in this batch; `u_si_reason` says why |
| `out_of_scope` | The record left the scope this target receives. A vulnerable item arrives closed, `u_close_reason` = `Out of scope`, never as fixed. A CI keeps its state. No more rows follow while it stays out of scope |

What the rules mean:

- **A missing row is never a deletion.** SecurityInsight never deletes a record, and closes one only on a `close` row.
- **Closes come only from complete runs.** A finding closes as `Remediated` only after it was absent for the required
  number of complete runs in a row (default 2) on an asset SecurityInsight saw. While that count runs, the item is
  `held`.
- **A scope never fixes anything.** A vulnerable item that leaves the scope closes as `Out of scope`, once. It reopens
  when it comes back in scope.
- **A record that leaves SecurityInsight's data** gets one `held` row with its last values, then no more rows. The record
  in your system stays as it is.
- **A vulnerable item whose CI is not delivered** in a complete batch (this one or an earlier one) is `held`, or not sent
  when your instance never had it, reason *its CI is not delivered yet*. When the CI output is switched off, this check
  is off and the run's log says so.

## One set of values

| Value | Column | Values |
|---|---|---|
| CI state | `u_si_state` | `active`, `not-seen`, `retired` |
| Vulnerable item state | `u_state` | `Open`, `Closed` |
| Close reason | `u_close_reason` | `Remediated`, `AssetRetired`, `NoLongerMonitored`, `Out of scope`, `Duplicate`, `Report changed`, `Linked`, `Rekeyed`, `ClosedByEngineer`, `No longer reported by SecurityInsight` |
| Batch state | `u_si_state` / `u_state` / `BatchState` | `writing`, `complete`, `failed`, `held` |
| Mode | `u_si_mode` / `Mode` | `live`, `resync`, `test` (`test` on the ServiceNow push only) |

**Only `Remediated` is a fix.** Map every other close reason to a close code that is not "fixed". The hand-off database,
the ServiceNow push and the SQL vulnerability connector use the same values.

## Clear or unknown

The Import Set API cannot tell an empty value from a value that was not sent, so the push leaves an empty value out of
the row. `u_si_cleared` says which empty values are real:

| On a row with `u_action` | A column listed in `u_si_cleared` | An empty column not listed |
|---|---|---|
| `new`, `update`, `close`, `reopen`, `out_of_scope` | SecurityInsight knows it is empty now: **clear your value** | Unknown: **keep your value** |
| `held` | (never listed) | Unknown: keep every value |

The clearable columns:

| Output | Clearable columns |
|---|---|
| CIs | `u_fqdn`, `u_dns_domain`, `u_serial_number`, `u_mac_address`, `u_object_id`, `u_azure_resource_id`, `u_aad_device_id`, `u_mde_device_id`, `u_entra_object_id`, `u_tier`, `u_tier_reason`, `u_criticality`, `u_exposed_internet`, `u_data_sensitivity`, `u_si_asset_subtype` |
| Vulnerable items | `u_cmdb_ci`, `u_severity`, `u_closed_at`, `u_close_reason`, `u_title`, `u_si_component`, `u_si_servicenow_subci`, `u_si_os_family`, `u_si_patch_cycle` |

SQL targets: SecurityInsight writes the whole row, so `NULL` on a row SecurityInsight wrote is the clear. A `held` record
is not written.

## Who wins

| Situation | What happens |
|---|---|
| SecurityInsight still sees the finding, and an engineer closed the record in your system | Every row says `Open` (`update`). **Your importer reopens the record**, with the reason. The SQL vulnerability connector reopens it itself |
| SecurityInsight no longer sees the finding | It closes only after the absence was counted over complete runs (`held` until then), with the reason |
| Your system says a record is closed | SecurityInsight never closes on the target's word |

## Re-keying

A device that is re-onboarded, or two records that turn out to be one asset, can give a CI a new key. Then:

1. The row under the **new** key carries `u_si_replaces` = the **old** key. For a vulnerable item:
   `<old CI key>|<finding key>`.
2. Your importer **moves** the record found by the old key to the new key (it does not create a second record).
3. The old key gets no row of its own. Once the batch with `u_si_replaces` is complete, the old key leaves the state and
   `u_si_replaces` is not sent again.

Import every complete batch, oldest first: a re-key, an `out_of_scope` row and the `held` row of a record that left
SecurityInsight's data arrive once.

## Scope

An admin sets what each target receives on **Configuration > Connectors > Scope**. The scope is applied when sending:

| Scope on the page | Applies to | Filters |
|---|---|---|
| CMDB connector (ServiceNow) | The CIs of the ServiceNow push | Asset kind (endpoint, identity, azure, publicip), tier |
| Vulnerability connector (ServiceNow) | The vulnerable items of the ServiceNow push | Risk rating, severity, security domain, tier, and more filters on the finding's fields |
| CMDB connector (SQL) | The CMDB SQL connector | Asset kind, tier. CIs out of scope are left as they are |
| Vulnerability connector (SQL) | The SQL vulnerability connector | As the ServiceNow vulnerability scope |

A scope that cannot be read fails the output: a scope set by an admin never silently becomes "everything".

## Full resync and test batch

On **Configuration > Connectors > Setup**, the card **ServiceNow: one route** offers two buttons. Each proposes the
setting `SI_DataOut_ServiceNowRequest` on the settings page; an admin reviews and saves it there (change-logged). The next
sync carries it out once.

| Button | Setting value | What the next sync does |
|---|---|---|
| **Full resync...** | `resync:<token>` | Treats every base as none: every record in scope is `new`, every closed or retired record `close`. One batch per output, `u_si_mode` = `resync`. Import it like `live` |
| **Send a test batch...** | `test:<token>` | First sends one batch per output with at most 5 rows, id `<run id>:<output>:test`, `u_si_mode` = `test`, then the normal batch. A test batch changes no state in SecurityInsight. **Your importer never imports a `test` batch** |

A test batch needs the staging status table.

## The import result, read back

At the start of each sync of an output, SecurityInsight reads ServiceNow's own import result for its newest complete
`live` or `resync` batch that has none yet (up to 3 days old): the import set rows of the batch's import sets, counted
per import state. It writes a `feedback` row to the staging status table with the same `u_si_batch_id`:

| Column | Meaning |
|---|---|
| `u_si_import_inserted`, `u_si_import_updated` | Rows your import inserted or updated |
| `u_si_import_ignored` | Rows ignored, including rows your IRE *onBefore* script handed over and ignored |
| `u_si_import_skipped` | Rows skipped |
| `u_si_import_errors` | Rows in error. More than 0 raises a SecurityInsight issue for the output |
| `u_si_import_pending` | Rows not transformed yet; read again at the next sync |

The integration user needs read access to `sys_import_set_row` for this. Without it, the run logs a warning and the
batch is not affected. SQL connectors record the rows the batch wrote (`LandedRows`).

## Field ownership

- SecurityInsight owns every `u_si_*` column and every column it fills in the staging rows. Which of them may change
  your records is your reconciliation rules' decision: make SecurityInsight authoritative for its security attributes
  and the lowest-priority source for the rest.
- SecurityInsight only inserts staging rows. It never writes a `cmdb_ci*` or `sn_vul*` record, never deletes anything,
  and never touches a record it did not send.

## Personal data

- Identity CIs and their vulnerable items carry the names and user principal names of Entra identities (`u_name`,
  `u_asset_name`) and their Entra object ids.
- An identity SecurityInsight no longer sees moves to `not-seen` and `retired` like any CI. Once it is no longer in
  SecurityInsight's data, it gets one `held` row and then no more rows.
- SecurityInsight never deletes a staging row or a record. How long the import set rows are kept is yours: ServiceNow's
  **Import Set Deleter** removes them (see
  [Knowing when a sync is complete](servicenow-sync-complete#retention-how-long-servicenow-keeps-the-rows)).

## Volumes and limits

| Item | Value |
|---|---|
| Rows per call | 200, through `POST /api/now/import/<table>/insertMultiple` |
| Rows per batch | The output's full scoped state: in-scope CIs, or in-scope vulnerable items (open and closed) |
| Staging status rows | 2 per output per sync (`writing` and the end row), plus 1 `feedback` row, plus a `failed` row for a batch that never ended, plus 2 for a test batch |
| Rows per day, per output | (records in scope + 2 to 3 status rows) x syncs per day |
| Limits of your instance | The REST API's rate limits, the transaction quota and the import set size are your instance's. SecurityInsight tries a throttled call again and honors `Retry-After` |
| Recommended retention | At least the two newest complete batches of each output |

Example: 20,000 CIs and 150,000 vulnerable items in scope, one sync a day: about 170,000 data rows and 6 status rows a
day; kept seven days, about 1.2 million import set rows.

## Dates

Every date and time in every column is UTC, as `yyyy-MM-dd HH:mm:ss`: ServiceNow's own date-time format, so a field map
needs no date format. The SQL views give `datetime2` values in UTC.

Verified against SecurityInsight 3.0.0.202610261957 on 2026-10-27.
