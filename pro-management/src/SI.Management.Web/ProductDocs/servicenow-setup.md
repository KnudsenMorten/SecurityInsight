# Setting up ServiceNow for SecurityInsight

Your ServiceNow team does this. SecurityInsight changes nothing in ServiceNow. The connector page shows the same steps
under *How to set up the ServiceNow side* (hand-off database) and *ServiceNow: set up and verify* (ServiceNow push). What
the importer does with each record is on [Handling records and states](servicenow-records-and-states); the rules every
target shares are on [The SecurityInsight data contract](data-out-contract).

## Steps for every route

1. **Register the discovery source.** Add `SecurityInsight` as a choice on `cmdb_ci.discovery_source`. IRE refuses a
   payload from an unregistered source.
2. **Identification and reconciliation first.** Before the first SecurityInsight row is transformed:
   - keep your identification rules first; add `u_si_correlation_id` only as the last identifier entry;
   - add reconciliation rules: SecurityInsight authoritative for its own attributes (tier, tier reason, exposure, last
     seen, source run, state), the lowest-priority source for everything else (name, OS, IP, MAC, serial number, …).
   IRE lets the source that last wrote an attribute keep writing it, so a rule added later does not take back what
   SecurityInsight already wrote. IRE also sets `discovery_source` to the last source that touched a CI: it says who
   updated it last, not who owns it.
3. **Classes.** Map `u_proposed_class` to your classes, or override it. `cmdb_ci_vm_instance` is a dependent class:
   SecurityInsight does not carry the hosting chain, so match the VM the owning connector created (class and
   `object_id`) and set only SecurityInsight's attributes on it. A class for Azure resources that extends
   `cmdb_ci_vm_object` inherits `object_id`. Entra identity classes identify on the Entra object id.
4. **Build the transform maps.** A classic transform map has no "use IRE" switch. Use an *onBefore* script that hands the
   row to IRE and then sets `ignore = true`: `CMDBTransformUtil` with `setDataSource('SecurityInsight')` (one class per
   map), or `SNC.IdentificationEngineScriptableApi.createOrUpdateCIEnhanced('SecurityInsight', payload, {})` for the
   per-row class; or IntegrationHub ETL. Never set `error = true` in a transform script: it stops the rest of the
   import set.
5. **Field maps.** Map the columns as [ServiceNow staging tables and columns](servicenow-columns) says. An asset-keyed
   row (`u_id_source` = `asset`, hand-off database): identify first, and create nothing when IRE would insert. Key-values
   to `cmdb_key_value` (a Defender tag is a key without a value); relations to `cmdb_rel_ci`.
6. **Vulnerable items.** Through your Vulnerability Response transform, coalescing as [the keys](servicenow-columns#keys)
   say. The CI is the one whose `u_si_correlation_id` is the row's. A `cve` finding maps to its NVD entry; any other type
   to a third-party entry with `u_vulnerability` as its id and `u_title` as its name. Only `Remediated` closes as fixed.
   Never touch a record whose `u_source` is not `SecurityInsight`.
7. **State.** Decide what `u_si_state` `not-seen` and `retired` mean in your CMDB.
8. **Gate on the batch.** Import a batch only when it is complete (see
   [Knowing when a sync is complete](servicenow-sync-complete)).

## Hand-off database steps

1. **Data source:** *System Import Sets > Data Sources*, type *JDBC*, format *SQL Server*, *Use MID Server*, the hand-off
   database, query *Specific SQL*, one data source per view, for example `SELECT * FROM snowstage.vImportCi WHERE
   u_changed_at > ?` with your last import time.
2. **Import set table:** let the first *Test load* create it; every column is a `u_` column of the view. Check the
   lengths against [ServiceNow staging tables and columns](servicenow-columns).
3. **Schedule** the import after SecurityInsight's Deliver stage, and only when the batch is complete: in a database of
   your own, the newest `vImportBatch` row; for the vulnerable items in the Pro database, the newest
   `servicenow-vulnerable-item` row of `vImportBatch`.

## ServiceNow push steps

1. **Create the staging tables.** One import set table per output, extending *Import Set Row* (`sys_import_set_row`),
   for example `u_si_ci_import` and `u_si_vuln_import`, plus the **staging status table** `u_si_staging_status` (see
   [Create the staging status table](servicenow-sync-complete#create-the-staging-status-table)). The names your
   SecurityInsight admin sets must be custom (`u_…`) or scoped (`x_…`) tables; a record table is refused. Create every
   column with its exact name and at least the length the ServiceNow schema (JSON) gives: `u_si_correlation_id` 400 and
   `u_vulnerability` 100. A 40-character default cuts values. The connector page offers the JSON definition of all three
   tables under *For your ServiceNow team > Tables to create in ServiceNow*.
2. **Map by column name.** For each table, add a *REST Insert Multiple* record (`sys_rest_insert_multiple`, source table
   = the table) with a *Column mappings* row = **Column name**. Without it, `insertMultiple` matches the keys to the column
   **labels**: on a table whose labels are not the column names, every row lands with every column empty, with HTTP 200
   and nothing transformed. The insert runs asynchronously by default; the same record can make it synchronous.
3. **The transform.** Gate it on the staging status table, act on `u_action`, honor `u_si_cleared` and `u_si_replaces`
   (see the [example scripts](#example-transform-scripts)).
4. **The integration user and its roles** (see below).
5. **Give your SecurityInsight admin** the instance URL, the three table names, and the API key, or the user and the
   password.
6. **Network.** The instance must be reachable over https from Azure, where SecurityInsight runs. If your instance allows
   only listed IP addresses, add SecurityInsight's outbound address (your SecurityInsight admin has it).
7. **Test it.** Your SecurityInsight admin can send a test batch (**Send a test batch...** on the card *ServiceNow: one
   route*): at most 5 rows per output, mode `test`, which your importer never imports.

## Roles of the integration user

Every role and setting below goes on the ONE ServiceNow user SecurityInsight signs in as: the user name and password, or
the user an API key belongs to, that your SecurityInsight admin entered. **Every line is needed**: one left out stops the
sync or makes SecurityInsight warn on every run.

| Role | What for | Without it |
|---|---|---|
| `import_set_loader` and `import_transformer` | Sending rows through the Import Set API (`insertMultiple`), including the staging status rows | The send is refused (403) |
| `personalize_dictionary` | Reading the staging table (`sys_db_object`) and its columns (`sys_dictionary`) | ServiceNow answers 403 `unauthorized to access table: sys_db_object`. The check before each sync fails, and **nothing is sent** |
| `import_admin` | Reading the REST Insert Multiple column mapping (`sys_rest_insert_multiple`, `sys_rest_insert_multiple_column_mapping`) | A warning on every check: the mapping is not checked |
| Read on `sys_import_set_row` (`import_admin` gives it on a standard instance) | Reading your import's result per batch | A warning on every run; the import result is not shown |
| Read and create on the three staging tables -- for a **scoped application**'s tables (`x_<scope>_...`), the application's own role its access controls use | Writing the rows, and reading one row back after each page and each staging status row after it is written | The send or the read-back is refused (403) |

**Each of the three staging tables** (System Definition > Tables > the table > *Application Access*): *Accessible from* =
All application scopes; *Can read* and *Can create* on; *Allow access to this table via web services* on.

### Every call SecurityInsight makes

| Call | Access | What for |
|---|---|---|
| `GET /api/now/table/sys_db_object` | read (`personalize_dictionary`) | Does each staging table exist, does it extend Import Set Row |
| `GET /api/now/table/sys_dictionary` | read (`personalize_dictionary`) | Each staging table's columns, types and lengths |
| `GET /api/now/table/sys_rest_insert_multiple`, `.../sys_rest_insert_multiple_column_mapping` | read (`import_admin`) | The column mapping |
| `POST /api/now/import/<CI staging table>/insertMultiple` | create (import roles + the tables' role) | The CI rows |
| `POST /api/now/import/<vulnerable item staging table>/insertMultiple` | create (the same) | The vulnerable items, when that output is on |
| `POST /api/now/import/<staging status table>` | create (the same) | The batch's writing row and end row |
| `GET /api/now/table/<each staging table>` | read (the tables' role) | The read-back of one row per page and of each status row |
| `GET /api/now/table/sys_import_set_row`, `/api/now/stats/sys_import_set_row` | read (`import_admin`) | Your import's result per batch |

The section **For your ServiceNow team** on the connector page shows this same list, ticked from the newest checks.

## The credential

On **Configuration > Connectors > Setup**, the data-out connector signs in with **an API key** (ServiceNow's REST API
key, sent as `x-sn-apikey`) **or a user and a password** (Basic sign-in over https). Not both: with both named,
SecurityInsight signs in with the API key and says so; a user without a password is refused. A password stored as an
API key is refused by ServiceNow with 401. Only the Key Vault secret **names** are stored on the connector; a SuperAdmin
sets each value, which goes to your Key Vault and is never shown again. The instance URL is https only, a host name
without a path. The hand-off database needs no ServiceNow credential.

## What SecurityInsight checks before it sends

Before every sync, every day, and when an admin chooses **Verify connection** or **Verify table schema**,
SecurityInsight checks each output with the same credential the push uses:

1. **The connection:** one read of the staging table's own record (`sys_db_object`).
2. **The table:** it exists and extends Import Set Row.
3. **The columns** (`sys_dictionary`): every column it sends exists and is long enough.
4. **The column mapping** (`sys_rest_insert_multiple`): by name, by label, or not readable.
5. **The staging status table:** it exists, is an import set table and has every column.

A missing column, a value that would be cut, a mapping by label or a staging status table that is missing or short of a
column **holds** the push: the batch ends `held` (when the staging status table can be written), nothing is sent, and
every record goes again in the next batch once the table is right. A column type that differs, or an extra column of
yours, is said and never holds. The page shows the newest result per output; a failed check reaches *Data health*, the
heartbeat and the daily mail.

The section **For your ServiceNow team** on the connector page lists what is still to do (roles, tables, columns, the
REST Insert Multiple records, the discovery source, the network), ticked from the newest checks. **Copy** or the text
download hands it to you. It holds no secret and no secret name.

## Example transform scripts

The scripts below are examples to adapt: the field names on your target tables, your state and close code values and
your coalesce fields are yours. Each runs as the *onBefore* script of a transform map, started for a complete batch only;
`source` is the staging row, `target` the record the coalesce fields found, `action` is `insert` or `update`, and
`ignore = true` skips the row.

### Vulnerable items from the push

```javascript
// onBefore: transform map from the vulnerable item staging table (the push, with u_action).
// Coalesce: u_si_correlation_id + u_vulnerability (or u_source_record_id).
(function runTransformScript(source, map, log, target) {
    var OPEN = 'open-value';           // set to your instance's open state
    var CLOSED = 'closed-value';       // set to your instance's closed state
    var FIXED = 'fixed-code';          // your close code for a fix
    var NOT_FIXED = 'not-fixed-code';  // your close code for every other reason

    if (String(source.u_source) !== 'SecurityInsight') { ignore = true; return; }
    if (String(source.u_si_batch_id).indexOf(':test') > -1) { ignore = true; return; }  // a test batch
    var act = String(source.u_action);

    // a re-key: move the record found by the old key (look it up yourself before insert)
    if (source.u_si_replaces != '' && action === 'insert') {
        // find the record whose source record id is source.u_si_replaces, and update it to the new key
    }
    if (act === 'held') { ignore = true; return; }                  // change nothing
    if (act === 'close' || act === 'out_of_scope') {
        if (action === 'insert') { ignore = true; return; }         // never create a closed record
        target.state = CLOSED;
        target.close_code = (String(source.u_close_reason) === 'Remediated') ? FIXED : NOT_FIXED;
        target.close_notes = source.u_close_reason + (source.u_si_reason != '' ? ': ' + source.u_si_reason : '');
        return;
    }
    // new, update, reopen: SecurityInsight sees the finding - the record is open, also after an engineer's close
    if (action === 'update' && act === 'update' && String(target.u_si_row_hash) === String(source.u_row_hash)
        && String(target.state) === OPEN) { ignore = true; return; }   // nothing changed
    target.state = OPEN;
    target.u_si_row_hash = source.u_row_hash;
    // clear the fields SecurityInsight lists as empty now; keep every other empty field
    var cleared = String(source.u_si_cleared).split(',');
    for (var i = 0; i < cleared.length; i++) {
        if (cleared[i] === 'u_closed_at') { target.closed_at = ''; }  // map each listed column to your field
    }
})(source, map, log, target);
```

### Vulnerable items from the hand-off database

```javascript
// onBefore: transform map from the vulnerability import set (no u_action).
(function runTransformScript(source, map, log, target) {
    var OPEN = 'open-value', CLOSED = 'closed-value', FIXED = 'fixed-code', NOT_FIXED = 'not-fixed-code';
    if (String(source.u_source) !== 'SecurityInsight') { ignore = true; return; }
    var state = String(source.u_state);

    if (state === 'Closed') {
        if (action === 'insert') { ignore = true; return; }         // never create a closed record
        target.state = CLOSED;
        target.close_code = (String(source.u_close_reason) === 'Remediated') ? FIXED : NOT_FIXED;
        target.close_notes = source.u_close_reason;
        return;
    }
    target.state = OPEN;                                            // open, also after an engineer's close
})(source, map, log, target);
```

### CIs from the push

Every CI arrives every sync. Keep the row hash and the state on the CI (for example in fields `u_si_row_hash` and
`u_si_state`), and put these lines first in the *onBefore* script that hands the row to IRE:

```javascript
var act = String(source.u_action);
if (act === 'held' || String(source.u_si_batch_id).indexOf(':test') > -1) { ignore = true; return; }
var ci = new GlideRecord('cmdb_ci');
var key = (source.u_si_replaces != '') ? source.u_si_replaces : source.u_si_correlation_id;
if (act === 'update' && ci.get('u_si_correlation_id', key) &&
    String(ci.u_si_row_hash) === String(source.u_row_hash) &&
    String(ci.u_si_state) === String(source.u_si_state)) {
    ignore = true;   // nothing changed
    return;
}
// a re-key: when source.u_si_replaces is set, update the CI found by the old key to the new u_si_correlation_id
// clear only the fields listed in source.u_si_cleared; keep the value of every other empty field
```

## Connector scope

Each target has its own **scope** on **Configuration > Connectors > Scope**: what it receives of what SecurityInsight
finds. Nothing ticked = everything.

## Scope settings

| Scope | Destination name on the page | Filters | Applies to |
|---|---|---|---|
| Vulnerability connector (ServiceNow) | `vuln-servicenow` | Risk rating, Severity, Security domain, Tier, and under *+ Add filter*: Category, Subcategory, Class, Component, Patch cycle, OS family, ServiceNow sub-CI, any other SI field of the finding, and *Advanced: source report* | The vulnerable items of the ServiceNow push |
| Vulnerability connector (SQL) | `vuln-sql` | The same | The SQL vulnerability connector (the vulnerability view of the hand-off database) |
| CMDB connector (ServiceNow) | `cmdb-servicenow` | Asset kind, Tier | The CIs of the ServiceNow push |
| CMDB connector (SQL) | `cmdb-sql` | Asset kind, Tier | SecurityInsight's own CI table (not the hand-off views) |

The values:

- **Risk rating:** Critical, High, Moderate, Low. The quick choice *Critical and High only* ticks the first two.
- **Severity:** Very High, High, Medium-High, Medium, Low (Critical counts as Very High).
- **Security domain:** Endpoint, Identity, Azure, PublicIP. The quick choice *Devices and Azure only* ticks Endpoint and
  Azure.
- **Tier:** 0 to 3.
- **Asset kind:** endpoint, identity, azure, publicip.
- **Class:** device, identity, cloud_resource, public_ip. **Component:** OS, SQL, Network, Hardware, Browser, Office,
  Application, Other.

The rules:

- Several values ticked in one filter: any of them passes. Several filters: all must pass.
- Severity, tier, domain and asset kind: a row without a value passes.
- Every other filter (risk rating, component, …): a row without a value does **not** pass.
- The default of every scope is empty: everything passes.
- A record that leaves the scope gets one `out_of_scope` row on the push; a vulnerable item closes as `Out of scope`,
  never as fixed.

What each scope means for the rows you receive is on
[Handling records and states](servicenow-records-and-states#the-actions-on-the-push).

Verified against SecurityInsight 3.0.0.202610261957 on 2026-10-27.
