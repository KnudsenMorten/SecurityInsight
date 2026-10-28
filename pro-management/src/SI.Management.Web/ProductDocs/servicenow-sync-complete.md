# Knowing when a sync is complete

Import only what SecurityInsight finished writing. This page says how you know, for each route, what a sync sends, and
how long to keep the rows. The batch states are the same for every target (see
[The SecurityInsight data contract](data-out-contract#the-rule)).

## The import rule

> **Import a batch only when the staging status table has a row with `u_si_state` = `complete` for its `u_si_batch_id`
> and `u_si_mode` is `live` or `resync`. Then import exactly the data rows with that `u_si_batch_id`, each complete batch
> once, oldest first. Never import a `writing`, `failed` or `held` batch, and never a `test` batch.**

## The staging status table

When SecurityInsight sends rows to your staging tables through the Import Set API, it also writes to a third import set
table: the **staging status table** (`u_si_staging_status` unless your SecurityInsight admin names another). It tells
your importer when SecurityInsight starts sending a batch and when that batch is complete, so your importer never acts on
a push that stopped halfway.

### How a batch works

Each sync sends each output as **one batch**: the configuration items (`servicenow-ci`) first, then the vulnerable items
(`servicenow-vulnerable-item`). A batch holds the **full current state** of the output's records in scope, each row with
its `u_action`. Its id, `u_si_batch_id`, has the form `<SecurityInsight run id>:<output>`, for example
`7d1c…e2:servicenow-ci`.

1. **Before the first data row**, SecurityInsight writes a row with `u_si_state` = `writing`.
2. **Every data row** of the batch, in the CI staging table or the vulnerable item staging table, carries the same
   `u_si_batch_id`.
3. **After the last data row**, SecurityInsight writes a second row with the same `u_si_batch_id` and the end state:
   `complete`, `failed` or `held`, with the counts per action and the reason.

Every batch has two rows in the staging status table, one per state change, and the states only move one way:

```text
                  +--> complete   every planned row was accepted        -> import the batch
                  |
   writing  ------+--> failed     some rows were not accepted, or the   -> do not import
                  |               batch never ended
                  +--> held       stopped before or while sending       -> do not import

   feedback   information: your import's result, read back later        -> not a batch state
```

| Column | On the writing row | On the end row | On a feedback row |
|---|---|---|---|
| `u_si_batch_id`, `u_si_output`, `u_si_target_table`, `u_si_connector`, `u_si_version`, `u_si_contract_version` | yes | yes (the same values) | yes (the batch it reports on) |
| `u_si_source_run` | the run that sends the batch | the same | the run that read the result |
| `u_si_mode` | `live`, `resync` or `test` | the same | |
| `u_si_started_at` | when the batch started | the same time | when the result was read |
| `u_si_planned_rows` | | how many data rows the batch sent | |
| `u_si_finished_at` | | when the batch ended | |
| `u_si_batch_time` | | only on `complete`: when the batch became complete | |
| `u_si_sent_rows`, `u_si_failed_rows` | | rows ServiceNow accepted, and rows not accepted or not sent (0 on `complete`) | |
| `u_si_new_rows`, `u_si_update_rows`, `u_si_close_rows`, `u_si_reopen_rows`, `u_si_held_rows`, `u_si_out_of_scope_rows` | | the counts per action | |
| `u_si_import_set_ids` | | the import sets of the data rows, for diagnosis | |
| `u_si_reason` | | why the batch ended as it did | your import's result in words |
| `u_si_import_inserted` … `u_si_import_pending` | | | your import's result per import state |

A batch with no records in scope is still a batch: `writing`, then `complete` with `u_si_planned_rows` = 0. Your importer
knows that SecurityInsight ran.

### Create the staging status table

Your SecurityInsight admin finds everything below on the ServiceNow data-out connector's page, under **For your
ServiceNow team > Tables to create in ServiceNow**: the definition of all three tables with every column, the steps, a
**Copy** button and a JSON definition to download for each table. The test pack (**Download test pack**) holds the same
columns and example rows (`rest/u_si_staging_status.json`).

| | |
|---|---|
| Name | `u_si_staging_status` (your SecurityInsight admin can choose another name) |
| Label | SecurityInsight staging status |
| Extends | Import Set Row (`sys_import_set_row`) |
| Columns | Every column of [the staging status table](servicenow-columns#the-staging-status-table-u_si_staging_status), with its exact name, type and maximum length |

**Steps in ServiceNow:**

1. Open **System Definition > Tables** and select **New**.
2. Label: *SecurityInsight staging status*. Name: `u_si_staging_status` (ServiceNow adds the `u_` prefix itself; type
   `si_staging_status` if the form adds it). Extends table: **Import Set Row**. Leave *Create module* and *Create mobile
   module* off.
3. Add every column with exactly its column name, type and maximum length. The label is free; the name is what
   SecurityInsight sends. Save.
4. Add a **REST Insert Multiple** record for the table with **Column mappings = Column name**. SecurityInsight writes
   this table one row at a time, which maps by name; the record keeps it that way.
5. Give both data staging tables the contract's columns, `u_si_batch_id` among them (see
   [The contract's columns](servicenow-columns#the-contracts-columns)).
6. The integration user needs `import_set_loader` and `import_transformer`, as for the data staging tables, and read
   access to `sys_import_set_row` for the import result.
7. The staging status table needs no transform map: your importer reads it.
8. Tell your SecurityInsight admin the table name. If it is not `u_si_staging_status`, they set it in SecurityInsight
   (the setting *Data out: ServiceNow staging status table*).

SecurityInsight checks the staging status table before every sync, together with the data staging tables. If the table
is named but missing, is not an import set table, or lacks a column, **SecurityInsight sends nothing** and says why on
the ServiceNow page, in *Data health* and in the daily mail. It never sends data rows without their batch marker. When
the setting is empty, SecurityInsight sends the data rows without status rows and warns on the ServiceNow page, in the
ServiceNow check and in the daily mail: nothing then tells your importer when a sync is complete, and a test batch
cannot be sent.

### What your importer does in each state

| What the staging status table shows for a batch | What it means | What your importer does |
|---|---|---|
| `writing` only | SecurityInsight is sending | Wait. Do not import |
| `writing`, then `complete`, mode `live` or `resync` | Every row was accepted (`u_si_sent_rows` = `u_si_planned_rows`) | Import the data rows with this `u_si_batch_id`, once |
| `writing`, then `complete`, mode `test` | A test batch | Never import it. Check its rows by hand |
| `writing`, then `failed` | Some rows were not accepted; `u_si_failed_rows` and `u_si_reason` say how many and why | Do not import. The records go again in the next batch |
| `writing`, then `failed`, reason *a later sync started while this batch was still writing* | The batch never ended (for example the job was stopped); the next sync ended it | Do not import |
| `writing`, then `held` | SecurityInsight stopped before or while sending, for example on a check of your staging table; `u_si_reason` says why | Do not import. What you imported before stays as it is |
| `feedback` | Your import's result for an earlier complete batch, as SecurityInsight read it back | Nothing to import. Check `u_si_import_errors` |
| No new batch | SecurityInsight did not send this output (no sync, a sync that stopped before it started sending, or a data-health hold) | Nothing to do. What you imported before stays as it is |

**What "the records go again" means.** Every batch is the full state, so the next complete batch carries every record
again. A record's action is decided against what your instance received in a **complete** batch: when a batch does not
end `complete`, its rows count as not delivered, and the next batch decides them again (a first-time record is `new`
again).

### A batch that never ends

At the start of each sync, SecurityInsight ends every batch of the same output that is still `writing` as `failed`, with
the reason *a later sync started while this batch was still writing*, and writes a `failed` row for it. There is never
more than one open batch per output.

### The import result, read back

At the start of each sync of an output, SecurityInsight reads ServiceNow's import result for its newest complete `live`
or `resync` batch that has none yet (up to 3 days old) and writes a `feedback` row: rows inserted, updated, ignored,
skipped, in error and pending. Rows your IRE *onBefore* script handed over and ignored count as ignored. Errors raise a
SecurityInsight issue for the output, visible to your SecurityInsight admin; pending rows are read again at the next
sync. Without read access to `sys_import_set_row`, the run logs a warning and nothing else changes.

### Full resync and test batch

| Mode | Asked by | What the batch holds | Import it |
|---|---|---|---|
| `live` | Every sync | The full scoped state, actions decided against the last complete batch | Yes |
| `resync` | **Full resync...** on the card *ServiceNow: one route* | The full scoped state, every record in scope `new`, every closed or retired record `close` | Yes, like `live` |
| `test` | **Send a test batch...** on the same card | At most 5 rows per output, id `<run id>:<output>:test`, sent before the normal batch | Never |

Each button proposes the setting on the settings page; your SecurityInsight admin reviews and saves it, and the next sync
carries it out once.

## Start your import when a batch is complete

Pick one way to start your import. Each example is a starting point for your ServiceNow developers; adapt the names
and check the APIs on your ServiceNow release.

**Prepare the data staging tables.** For a gated import, the rows must wait in the data staging tables until their batch
is complete: run your transform from your own import script (below), not automatically when the rows arrive. If your
transform already runs as the rows arrive, see [My transform runs as the rows arrive](#my-transform-runs-as-the-rows-arrive).

**1. A Business Rule on the staging status table (starts at once).** An *after insert* Business Rule on
`u_si_staging_status`, condition `u_si_state` *is* `complete` and `u_si_mode` *is not* `test`, hands the batch to your
import script:

```javascript
// Business Rule: after insert on u_si_staging_status,
// condition: current.u_si_state == 'complete' && current.u_si_mode != 'test'
(function executeRule(current, previous) {
    // queue the work: an event your Script Action handles keeps the insert fast
    gs.eventQueue('x_acme.si.batch_complete', current, current.u_si_batch_id, current.u_si_output);
})(current, previous);
```

```javascript
// Script Action on the event x_acme.si.batch_complete: import exactly the rows of this batch
var batchId = event.parm1;
var output = event.parm2;
var table = (output == 'servicenow-ci') ? 'u_si_ci_import' : 'u_si_vuln_import';
var rows = new GlideRecord(table);
rows.addQuery('u_si_batch_id', batchId);
rows.query();
// Hand the rows to your transform: for example, run your transform map on each import set of these rows
// (ServiceNow's GlideImportSetTransformer API - check its use on your release), or process them in your own script.
```

**2. A scheduled job that polls (simple, and catches up after a pause).** A scheduled script runs every 15 minutes, finds
the complete batches it has not imported yet, oldest first, and imports each once:

```javascript
// Scheduled Script Execution, every 15 minutes
var last = gs.getProperty('x_acme.si.last_imported_batch_time', '1970-01-01 00:00:00');
var done = new GlideRecord('u_si_staging_status');
done.addQuery('u_si_state', 'complete');
done.addQuery('u_si_mode', 'IN', 'live,resync');
done.addQuery('u_si_batch_time', '>', last);
done.orderBy('u_si_batch_time');
done.query();
while (done.next()) {
    importBatch(String(done.u_si_batch_id), String(done.u_si_output));          // your import, as in the Script Action above
    gs.setProperty('x_acme.si.last_imported_batch_time', String(done.u_si_batch_time));
}
```

**3. A transform map on the staging status table.** If your team prefers transform maps, a transform map on
`u_si_staging_status` with an *onAfter* script that calls your import script for a row whose `u_si_state` is `complete`
and whose `u_si_mode` is not `test` works the same way as the Business Rule.

### My transform runs as the rows arrive

Many integrations transform each row as it arrives. That stays safe for row-by-row updates, because every row is matched
on its key (`u_si_correlation_id`, plus `u_vulnerability` for a vulnerable item), so a row sent twice never makes a
second record. Two things still need the batch:

- **Skip `test` batches**: a row whose `u_si_batch_id` ends in `:test` is never imported.
- **Every decision that depends on the whole batch** waits for the `complete` row: counts and reports, and anything
  your process does for records that are not in a batch.

## Questions your ServiceNow team asks

**Can two batches of the same output overlap?** No. SecurityInsight runs one pipeline at a time, never starts a job that
is already running, and ends a batch still `writing` before it opens the next one. If you ever see two complete batches
you have not imported, import each once, ordered by `u_si_batch_time`.

**What happens when a sync is run again?** Each sync has its own run id, so it sends a new batch with a new
`u_si_batch_id`. A batch id never comes back. A row that was already imported and comes again matches the same record
(by its key), so it updates it and never makes a second one.

**Do we have to import every complete batch?** Yes, oldest first. Each batch is the full state, but some rows arrive
once: `out_of_scope`, the `held` row of a record that left SecurityInsight's data, and `u_si_replaces` after a re-key.

**What happens to the rows of the previous complete batch?** Nothing. SecurityInsight never deletes or changes anything
in ServiceNow; it only adds rows through the Import Set API. What you imported from earlier batches stays as it is.

**In which order do the two outputs arrive?** The CI batch first, then the vulnerable item batch of the same run
(`u_si_source_run`). A vulnerable item whose CI is not delivered in a complete batch is held. Import the CI batch before
the vulnerable item batch of the same run.

**What if the end row cannot be written?** The batch stays `writing`, so your importer never imports it. The next sync
ends it as `failed`, and its records go again.

## Retention: how long ServiceNow keeps the rows

SecurityInsight only inserts rows through the Import Set API. **It never deletes anything in ServiceNow**, so your
ServiceNow team decides how long the staging rows are kept.

**ServiceNow's own cleanup.** ServiceNow removes old import sets with the **Import Set Deleter** scheduled job (open
**System Import Sets > Import Set Tables > Scheduled Cleanup**; it needs the admin role). By default it deletes import sets
and their import set rows that were created **more than seven days ago**. The job's *Run this script* field holds the
script that does the deletion, and the schedule sets how often it runs. Check the job and its default on your ServiceNow
release before you rely on these values.

**What your team keeps:**

- At least the rows of the **two newest complete batches of each output**. Never delete the rows of the newest complete
  batch before the next batch of that output is complete and imported.
- The staging status rows **as long as the data rows**: the importer needs a batch's `complete` row to know its rows may
  be imported.
- A margin for a pause: if SecurityInsight does not send for a few days (for example during a maintenance window), the
  newest complete batch must still be there, or already imported. Keep at least **14 days**, or seven days plus the
  longest pause you plan for, when your importer does not import each complete batch within hours.

**How the cleanup and a batch fit together.** ServiceNow's cleanup works on whole import sets, by when each import set was
created. One batch spans several import sets: the data rows are sent in calls of up to 200 rows, and ServiceNow can make
an import set per call, plus the import sets of the status rows. All of them are created within one push, so a cleanup
that keeps import sets for days keeps a batch whole, unless the cleanup's cut-off falls in the middle of a push. That
happens only to a batch that is days old by then. Import each complete batch within hours, and keep the retention at
least twice the time between two batches of the same output.

**The staging rows hold personal data.** Identity CIs and their vulnerable items carry names and user principal names of
Entra identities. Your retention is also how long ServiceNow keeps that data in staging.

### Sizing

Every sync sends the full scoped state, so the rows per batch are the records in scope:

```text
rows per day   =  (records in scope  +  2 to 3 status rows)  x  syncs per day     - per output, then add both outputs
rows kept      =  rows per day  x  days kept
```

- *Records in scope*: the CIs in scope for the CI output; the vulnerable items in scope, open and closed, for the other.
  The `u_si_planned_rows` of recent end rows give the numbers; *Configuration > Connectors > Fields sent* counts the rows
  the outputs would send.
- *Status rows*: `writing` and the end row, plus a `feedback` row (and a `failed` row for a batch that never ended, or
  2 rows for a test batch).
- *Syncs per day*: once a day by default (the daily pipeline); more if your SecurityInsight admin runs it more often.
- *Days kept*: the cleanup's retention (seven by default).

For example: 20,000 CIs and 150,000 vulnerable items in scope, one sync a day, kept seven days:
(20,003 + 150,003) x 1 x 7 = about 1.19 million rows.

## The hand-off database

### A database of your own: batches

A hand-off database of your own (a SecurityInsight connector of kind **sql**, direction **cmdb**) receives one
**batch** per run, listed in `snowstage.vImportBatch`:

| `u_state` | What it means | What you do |
|---|---|---|
| `writing` | SecurityInsight is writing the batch | Wait. The views do not show it |
| `complete` | Written whole; the row count was checked before the flag was set | Import. The views show the newest complete batch |
| `held` | Stopped by the mass-change guard: more of the previous batch's active CIs are missing than the limit allows | Nothing. The views keep showing the previous complete batch |
| `failed` | The write did not finish | Nothing. The views keep showing the previous complete batch |

How a batch is written:

1. **Never from a partial collection.** When a kind of asset (devices, Azure resources or identities) or the
   correlation results could not be read, or the collection holds no CI, no batch is written.
2. **The complete flag last.** Rows go in with `writing`; one statement then marks the batch `complete`. An import that
   runs while SecurityInsight writes reads the previous batch, whole.
3. **The mass-change guard.** The limit is the connector's `changeGuardPercent`, else the CMDB change limit on
   *Operations > Guards (safety checks)*, else 10 (percent). CIs that appear for the first time never trip it. An Admin
   releases a held batch once on *Operations > Guards (safety checks)* (see [Guards](guards)); a later run within the
   limit goes through by itself.
4. **Older batches are removed** after a batch completes. The newest 3 complete batches stay (`keepBatches`, at least 2).

To check a batch before you import: read the newest row of `vImportBatch`, make sure it is `complete`, and compare
`u_ci_count`, `u_key_value_count` and `u_relation_count` with the rows your import read. `u_reason` gives the counts of a
complete batch and the reason a batch was held.

### The Pro database and the SQL connectors

- **CIs, tags, relations, proposed CIs.** The views read the hand-off tables directly; a run updates the rows in place,
  in chunks. A kind of asset that could not be read keeps its rows as they were (one run old). Schedule your import after
  the data sync step has finished; its run is on *Configuration > Connectors > Runs*. A run that could not write the rows
  says *the ServiceNow hand-off rows were not written*: do not import that run's views as whole.
- **Vulnerable items.** `vImportVulnerableItem` carries `u_si_batch_id`, the batch of the SQL vulnerability connector
  that last changed the record. Import when the newest `servicenow-vulnerable-item` row of `snowstage.vImportBatch` is
  `complete`. The connector writes record by record, not in one transaction, so changed records can be visible before the
  `complete` row; a record gets its batch id when that batch ends.
- **SecurityInsight's CI table.** The CMDB SQL connector writes its batch row first (`writing`) and sets `complete` in
  the same transaction as the CI changes (`cmdbsync.SyncRun`, listed in `vImportBatch` as `servicenow-ci`). A reader
  never sees a CI change without the `complete` row.

## Both ways read the same

The push and the hand-off database use the same batch words, so one importer design fits both:

| | ServiceNow push | Hand-off database (Pro database) | Hand-off database of your own |
|---|---|---|---|
| Where the batch state is | The staging status table (`u_si_staging_status`) | `snowstage.vImportBatch` | `snowstage.vImportBatch` |
| The batch id | `u_si_batch_id` | `u_si_batch_id` (and `u_batch_id`) | `u_batch_id` |
| The state | `u_si_state` | `u_state` | `u_state` |
| The states | `writing`, `complete`, `failed`, `held` | the same | the same |
| When it started | `u_si_started_at` | `u_started_at` | `u_started_at` |
| When it became complete | `u_si_batch_time` | `u_batch_time` | `u_batch_time` |
| Why | `u_si_reason` | `u_reason` | `u_reason` |
| Which connector | `u_si_connector` | `u_connector` | `u_connector` |
| The rule | Import a batch only when its `complete` row exists | Act only on rows of a complete batch | The import views show only the newest complete batch |

## What a sync sends

### The ServiceNow data-out connector

One ServiceNow connector with direction **data-out** feeds both outputs:

| Output | What one row is | Its table setting |
|---|---|---|
| **ServiceNow CI hand-off** | One configuration item | *Data out: ServiceNow CI Import Set table* |
| **ServiceNow vulnerable items** | One finding on one CI | *Data out: ServiceNow vulnerable item Import Set table* |

- **Switched on = it sends.** Switched off, nothing is sent and the run says so.
- **Exactly one** data-out connector may be switched on. With two switched on, nothing is sent to either, and the check
  fails naming both. None switched on: nothing is sent, and no failure is raised.
- Each output can be switched off on its own on *Configuration > Connectors > Fields sent*.
- An output whose table setting is empty is not written, and its run says so.
- The connector reaches only the Import Set API. It never writes a record directly.
- When SecurityInsight's own data health is *Unhealthy*, data out is held per channel until a SuperAdmin lets it through
  (*Configuration > Connectors > Data-health hold*). A held output sends no batch, and what it sent before stays as it was.

### What one sync sends

The outputs run at the end of the data sync step, the CI output first. For each output, SecurityInsight:

1. checks the connection, the staging tables and their columns, and the staging status table;
2. ends a batch of the output still `writing` as `failed`, and reads back the import result of the newest complete batch;
3. writes the `writing` row;
4. reads the CIs (or the findings per CI) from its database, 5,000 at a time, applies the output's scope, decides each
   record's `u_action`, and sends every row in calls of 200;
5. sends the records it sent before that are not in this sync's data (a `held` row where the rules say so);
6. writes the end row with the counts per action.

What is never sent: a record out of scope that your instance never had, or has closed; a record SecurityInsight already
told you left its data; CIs with the class public IP (the CI output sends devices, Azure resources and identities).

## Volumes and timing

- **Rows per call:** 200, through `POST /api/now/import/<table>/insertMultiple`. When the first call answers 400, 404 or
  405, SecurityInsight falls back to one row per call (`POST /api/now/import/<table>`) for the rest. Each staging status
  row is one call.
- **Calls per sync:** per output, the records in scope divided by 200, rounded up; one read-back after the first call of
  each page of up to 5,000 records; two calls per status row (the write and its read-back); one or two calls for the
  import result. Example: 30,000 vulnerable items in scope are 150 calls, 6 read-backs and about 8 calls for status rows
  and the import result.
- **When:** in the Deliver stage of the daily pipeline, at the end of the data sync step.
- **How long:** each call waits up to 120 seconds for an answer. The run time is set by your instance's answer time per
  call of 200 rows; SecurityInsight logs each output's time as *timing: data out …* in the step's log.
- **Throttling and network errors:** a 429, 408, 502, 503 or 504, or no answer, is tried again up to 4 attempts in all,
  waiting as long as ServiceNow's `Retry-After` says, else 2, 4 and 8 seconds. A 401 or 403 is not tried again. A 400 or
  500 is not tried again: it says the request must be fixed. Sending a row twice is safe: your transform coalesces it.
  Your instance's REST rate limits and transaction quota apply.
- **What a failure looks like:** the batch ends `failed` or `held` in the staging status table, and the run's line on
  *Configuration > Connectors > Runs* and the step's log say why. The next batch carries every record again.

Verified against SecurityInsight 3.0.0.202610261957 on 2026-10-27.
