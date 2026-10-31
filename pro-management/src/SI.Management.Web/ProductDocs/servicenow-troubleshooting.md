# ServiceNow troubleshooting and FAQ

What to do when SecurityInsight reports a problem with ServiceNow, and answers to the questions ServiceNow teams ask
most.

## Messages, causes and fixes

The messages below appear on the connector page, in the run's line on *Configuration > Connectors > Runs*, in the
step's log, and (for a batch) in `u_si_reason` of the staging status table. Each shows the start of the message.

### Connection and credential

| Message | Cause | Fix |
|---|---|---|
| `no ServiceNow data-out connector is switched on` / `is set up` | No data-out connector, or it is switched off | Set one up and switch it on |
| `ServiceNow data-out connectors are switched on:` | Two or more switched on; nothing is sent to any | Switch all but one off |
| `the ServiceNow data-out connector … is not valid:` | The connector's settings have a problem | Fix what the message lists |
| `no Import Set table is set` | The output's table setting is empty | Set *Data out: ServiceNow CI (or vulnerable item) Import Set table* |
| `names no API key and no user and password` | No credential chosen | Choose an API key, or a user and a password |
| `a user needs a password, and a password needs a user` | Half a credential | Set both, or choose an API key |
| `names an API key and a user / password` | Both ways named (a warning) | Choose one; the API key is used |
| `no ServiceNow instance address is set` | No instance URL | Set it on the connector page |
| `the Key Vault secret '…' (…) could not be read` | The secret is missing, or the job identity may not read it | Set the value again on the connector page |
| `The instance's name could not be found (DNS).` | Wrong instance URL | Correct the URL |
| `No secure connection (TLS) could be made` | Certificate refused, or a proxy replaces certificates | Correct the URL; allow the traffic |
| `The instance did not answer in time.` | Timeout | Tried again on the next sync |
| `The instance could not be reached:` | Network | Allow https from Azure; check an IP allow list |
| `ServiceNow refused the sign-in (401)` | Wrong or expired key or password, or not allowed for the REST API; a password stored as an API key | Set the credential again, the right way |
| `ServiceNow refused the request (403): it says the user needs the role ...` | ServiceNow named the missing role | Grant that role (see [Roles of the integration user](servicenow-setup#roles-of-the-integration-user)) |
| `ServiceNow refused the request (403): this user may not do it` | ServiceNow named no role: an access rule (ACL) of the instance refuses the table named after "ServiceNow said" | Grant the role SecurityInsight usually needs (named in the message) or an ACL that gives the same access. When it is `sys_db_object` / `sys_dictionary`, SecurityInsight checks the staging table itself and sends anyway; only the column check is left out (a warning) |
| `the integration user was refused` | 401 or 403 on a call | Check the credential and the table's access rules |
| `The ServiceNow connector is part of SecurityInsight Pro` / `the ServiceNow hand-off is part of SecurityInsight Pro` | The license does not include it | Nothing is sent |

### Staging tables

| Message | Cause | Fix |
|---|---|---|
| `The table … does not exist on the instance (404)` / `Connected, but the table … does not exist` | The staging table is missing or misspelled | Create it from the ServiceNow schema (JSON) |
| `The table … exists, but it does not extend Import Set Row` | A table that is not an import set table | Create it extending `sys_import_set_row` |
| `The columns could not be read:` / `could not be read whole` | No `personalize_dictionary`, or a very wide table | Grant the role |
| `No REST Insert Multiple record for …` / `matches the columns by LABEL` / `has no column mapping` | Rows would land empty | Add the REST Insert Multiple record with Column mappings = Column name |
| `The column mapping could not be read:` | No `import_admin` (a warning) | Grant it, or check the mapping by hand |
| `the column … is missing in …: its values would be lost` | A column is missing, a contract column too; the push is held | Add the column |
| `value(s) of … are longer than the column` | A column is too short; the push is held | Make it as long as the schema says |
| `the column … of … is not sent by SecurityInsight` | A column of yours SecurityInsight does not fill (information) | Nothing |
| `held, nothing was sent` / `held, nothing more was sent` | The check found one of the problems above; the batch ends `held` | Fix it; every record goes in the next batch |
| `the rows reached … EMPTY` | The first call's rows arrived empty: mapping by label | Add the REST Insert Multiple record; nothing more was sent |
| `is a ServiceNow record table, not a staging table` / `is not an import set table` / `is not a ServiceNow table name` / `no staging table is configured` | The table setting names a record table, a non-`u_`/`x_` table, or nothing | Set the import set table's name |

### The staging status table and batches

| Message | Cause | Fix |
|---|---|---|
| `The staging status table … does not exist on the instance` | The table is named but missing; nothing is sent | Create it (see [Create the staging status table](servicenow-sync-complete#create-the-staging-status-table)) |
| `The staging status table … is missing … column(s):` | A status column is missing; nothing is sent | Add the columns it names |
| `the staging status table: …` / `is also a data staging table` | The setting names a record table, or one of the data tables | Name a table of its own (default `u_si_staging_status`) |
| `The staging status table … does not extend Import Set Row.` | Not an import set table (a warning) | Create it extending `sys_import_set_row` |
| `the staging status table could not be written` | The `writing` row was refused; nothing is sent | Check the roles and the table, then the next sync sends |
| `the end row (…) could not be written` | The batch stays `writing` and is never imported; an error of the run | The next sync ends it as `failed` and sends every record again |
| `no staging status table is set` | The setting is empty; rows go without status rows (a warning) | Create the table, then set *Data out: ServiceNow staging status table* |
| `a later sync started while this batch was still writing` | A batch never ended (for example the job was stopped); ended as `failed` | Nothing: its records went in the next batch |
| `its CI (…) is not delivered in a complete batch yet` | A vulnerable item is held until its CI's batch is complete | Check the CI batch of the same run |
| `the CI output is switched off - the vulnerable items are sent without the check` | The CI output is off (information) | Switch it on if your vulnerable items need their CI first |
| `the re-keyed CIs could not be read` | No `u_si_replaces` this sync (a warning) | Nothing; the next sync tries again |
| `the import result of batch … could not be read back` / `may not read sys_import_set_row` | No read access to `sys_import_set_row` (a warning) | Grant read on `sys_import_set_row` to see the import result |
| `your import of batch …` with errors above 0 | Your import reported rows in error; a SecurityInsight issue is raised for the output | Look at the import set rows of the batch (`u_si_import_set_ids`) and fix the transform |
| `SI_DataOut_ServiceNowRequest '…' is not '<resync|test>:<token>' - ignored` | The request setting holds another value | Use the buttons on the card *ServiceNow: one route* |
| `a test batch was asked for, but it needs the staging status table` | No staging status table; the test batch is not sent | Create the table, then ask again |

### Calls and the hand-off database

| Message | Cause | Fix |
|---|---|---|
| `this is a request defect, not a platform failure` | ServiceNow answered 400 or 500 | Read ServiceNow's text in the message; fix the table or the transform |
| `gave up after … attempt(s)` | Throttling or network errors on every attempt | The batch ends `failed`; every record goes in the next batch |
| `the transform reported:` | One-row mode, synchronous transform, a row failed (a row your *onBefore* script ignored is not counted) | Fix the transform |
| `could not be read this run, so no batch is written` | A kind of asset could not be read (database of your own) | Nothing to do; the previous batch stays |
| `the asset correlation results could not be read` | Correlation not readable (database of your own) | Nothing to do; the previous batch stays |
| `HELD` (mass-change guard) | More CIs missing than the limit | Check the collection; release once on *Guards* if it is real |
| `the Pro database does not have the ServiceNow hand-off tables yet` | The hand-off schema is not installed | Your SecurityInsight admin runs the database setup once |
| `the ServiceNow hand-off rows were not written` | The Pro database write failed | Do not import this run's views as whole; the next run writes them |

## FAQ

**How do we know a sync is done?** Push: the staging status table has a `complete` row for the batch, mode `live` or
`resync`. Database of your own: the newest `vImportBatch` row is `complete`. Pro database: after the data sync step, and
for the vulnerable items the newest `servicenow-vulnerable-item` row of `vImportBatch` is `complete`. See
[Knowing when a sync is complete](servicenow-sync-complete).

**How do we see what changed?** Push: every record arrives every sync with `u_action`; an `update` with the
`u_row_hash` you keep is unchanged. Hand-off database: `u_changed_at` later than your last import.

**Why does every CI arrive on every sync?** The push sends the full current scoped state, so a batch is complete on its
own and nothing depends on an earlier batch having arrived. Skip unchanged `update` rows on `u_row_hash`.

**What if a CI disappears from SecurityInsight?** It is not deleted. It moves to `not-seen` after the seen window and to
`retired` after its grace period (`u_action` = `close`). Its open vulnerable items close as `AssetRetired` when it
retires. A record that leaves SecurityInsight's data gets one `held` row and then no more rows.

**What if a record stops arriving?** Missing is not deleted. Act only on the rows: `u_action`, `u_si_state`, `u_state`.

**An engineer closed a vulnerable item, and SecurityInsight reopens it.** SecurityInsight still sees the finding, so
every row says `Open` and your importer reopens the record. SecurityInsight closes a record only on its own evidence,
never because your instance says it is closed.

**What does `u_si_cleared` change?** The listed columns are empty in SecurityInsight now: clear them. An empty column
that is not listed is unknown: keep your value.

**Can SecurityInsight overwrite our fields?** Only through your transform. SecurityInsight writes staging rows; your
reconciliation rules decide which attributes it may set. Make it authoritative for its security attributes and the
lowest-priority source for the rest.

**Can SecurityInsight create CIs?** Not by itself. Whether IRE creates a CI from a row is your transform's and IRE
rules' decision. The proposed CIs report lists the assets no CMDB CI matches.

**What if a push is sent twice?** Your transform coalesces on the keys, so a row sent twice updates the same record.

**Why do closed items close as something other than Remediated?** Because only an absence on an asset SecurityInsight
saw, over complete runs, is evidence of a fix. Every other reason is bookkeeping and must not count as fixed.

**Which identities and Azure resources arrive?** Devices, Azure resources and Entra identities (users, service
principals, managed identities, groups). Public IP addresses are a property, never a CI.

**Do tags and relations come through the push?** No. Only the hand-off database carries them.

**How do we get everything again?** Ask your SecurityInsight admin for **Full resync...** on the card *ServiceNow: one
route*: the next sync sends every record in scope as `new`, mode `resync`.

**Settings of an earlier ServiceNow push still hold values.** SecurityInsight ignores them; the update says once in its
log which of them still hold a value (*the older ServiceNow push was removed*), and leaves them in place. Nothing is
deleted.

Verified against SecurityInsight 3.0.0.202610261957 on 2026-10-27.
