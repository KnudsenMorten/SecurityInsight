# ServiceNow staging tables and columns

Every table and every column SecurityInsight hands to ServiceNow, with its type, when it is filled, what it means, the
ServiceNow field it maps to, and an example. What your importer does with each value is on
[Handling records and states](servicenow-records-and-states); the rules every target shares are on
[The SecurityInsight data contract](data-out-contract).

## The ServiceNow push

The ServiceNow data-out connector writes to three import set tables on your instance:

| Table (suggested name) | Output | One row per |
|---|---|---|
| `u_si_ci_import` | ServiceNow CI hand-off (`servicenow-ci`) | CI in scope, every sync |
| `u_si_vuln_import` | ServiceNow vulnerable items (`servicenow-vulnerable-item`) | Vulnerable item in scope (CI and finding), open or closed, every sync |
| `u_si_staging_status` | Both | Batch state change: `writing`, then `complete`, `failed` or `held`; plus `feedback` rows |

Your SecurityInsight admin sets the names: *Data out: ServiceNow CI Import Set table*, *Data out: ServiceNow vulnerable
item Import Set table* and *Data out: ServiceNow staging status table* (`u_si_staging_status` when not set). Each must be
a custom (`u_…`) or scoped (`x_…`) import set table; the staging status table must be a table of its own.

*Configuration > Connectors > Fields sent* shows the columns in force for each output (an admin can rename, move or remove
a content column; the contract's columns are always sent) and offers **ServiceNow schema (JSON)** and **ServiceNow team
pack (Excel)** to build the staging tables from. The connector page offers the JSON definition of all three tables under
*For your ServiceNow team > Tables to create in ServiceNow*.

## The hand-off database

SecurityInsight writes its views into the schema `snowstage` of a SQL database. Your MID Server reads the views through a
JDBC data source into an import set. SecurityInsight holds no ServiceNow credential on this route.

### Where the views live

- **The Pro database** (the default). The views `vImportCi`, `vImportCiKeyValue`, `vImportCiRelation`, `vProposedCi`,
  `vImportVulnerableItem` and `vImportBatch`. The CI, tag, relation and proposed CI rows are updated in place by each
  run. `vImportVulnerableItem` carries `u_si_batch_id`, the batch of the SQL vulnerability connector that last changed
  the record; `vImportBatch` lists the batches of the CMDB SQL connector and the SQL vulnerability connector.
- **A hand-off database of your own.** Add a connector on **Configuration > Connectors > Setup** with kind **sql** and
  direction **cmdb**, and give its `server` and `database`. That database holds `vImportCi`, `vImportCiKeyValue`,
  `vImportCiRelation` and `vProposedCi`, each with the batch columns (and the CI view with owner and department), plus
  its own `vImportBatch`. It does **not** hold the vulnerable items: read `vImportVulnerableItem` from the Pro database.

### What each view holds

| View | One row per | What it holds |
|---|---|---|
| `snowstage.vImportCi` | CI | Devices, Azure resources and identities: identifiers, security attributes, state |
| `snowstage.vImportCiKeyValue` | CI, source and key | Azure tags and Defender machine tags, present or removed |
| `snowstage.vImportCiRelation` | parent, child and type | A VM's OS and data disks, network interfaces and user-assigned identities, present or removed |
| `snowstage.vProposedCi` | CI | CIs no CMDB CI is known to match, with the evidence. A report; nothing is created from it |
| `snowstage.vImportVulnerableItem` | CI and finding | Every finding on a CI, open or closed with the reason (Pro database only) |
| `snowstage.vImportBatch` | batch | The batches and their states (see [Batches](#batches-vimportbatch)) |

### Batches in a database of your own

A hand-off database of your own receives one **batch** per run:

1. **Never from a partial collection.** If a kind of asset (devices, Azure resources or identities) or the correlation
   results could not be read, or the collection holds no CI, no batch is written. ServiceNow keeps importing the
   previous one.
2. **The complete flag last.** Rows go in with the batch state `writing`. One statement then marks the batch
   `complete`, after its row count is checked. The import views show only the **newest complete batch**, so an import
   that runs while SecurityInsight writes reads the previous batch, whole.
3. **The mass-change guard.** When more than 10% of the previous batch's active CIs are missing from this one, the batch
   is recorded as `held` and never shown. ServiceNow keeps the previous batch. The limit is the connector's
   `changeGuardPercent`, else the CMDB change limit on *Operations > Guards (safety checks)*, else 10. CIs that appear for
   the first time never trip it. An Admin releases a held batch once on *Operations > Guards (safety checks)* (see
   [Guards](guards)); a later run that is back within the limit goes through by itself.
4. **A failed write** leaves the batch in state `failed`. It is never shown.
5. **Older batches are removed** after a batch completes. The newest 3 complete batches stay (`keepBatches`, at least 2).
6. **The data is the same either way.** A CI SecurityInsight no longer sees is carried into every batch with its state.

### The Pro database

- The CI, tag, relation and proposed CI views read the hand-off tables directly. A run updates the rows in place, in
  chunks. A kind of asset that could not be read keeps its rows exactly as they were (one run old), and the run says so.
  A run that could not write the rows fails with *the ServiceNow hand-off rows were not written*. Schedule your import
  after the data sync step has finished, and check its run on *Configuration > Connectors > Runs*.
- The vulnerable items follow the SQL vulnerability connector's batches: import when the newest
  `servicenow-vulnerable-item` row of `vImportBatch` is `complete`.

### Database permissions

In the hand-off database, SecurityInsight's job identity needs `db_datareader` and `db_datawriter`, plus `db_ddladmin`
for the first run that creates the tables. The account your MID Server connects with needs `db_datareader` only.

## Keys

### The CI key

`u_si_correlation_id` is SecurityInsight's key for one CI. Coalesce your staging transform on it.

- **ServiceNow push:** the CI id from SecurityInsight's CI table, minted once per real-world object by the identity
  ledger. `u_id_source` is always `ledger`. It survives re-imaging, a renamed device and a rotated Defender or Entra id.
  When a CI does get a new key, the row under the new key names the old one in `u_si_replaces` (see
  [Re-keying](data-out-contract#re-keying)).
- **Hand-off database:** the identity ledger's correlation id when the asset has one (`u_id_source` = `ledger`), else the
  asset's own id (`u_id_source` = `asset`). An asset id changes once, when the ledger mints the CI's id: do not create a
  CI from an asset-keyed row. A provisional correlation id is never used as a key.
- The two routes take the key from different places. Do not feed one staging table from both routes.
- Treat the key as an opaque string of up to 400 characters (for example `mdedeviceid:…`, `azureresourceid:…`,
  `entraobjectid:…` or a UUID). Make the column 400 long.
- The CI rows and the vulnerability rows of one route carry the **same** key, so each vulnerable item finds its CI.

In IRE, keep your own identification rules first. Add `u_si_correlation_id` (on the CI, for example as a field
`u_si_correlation_id`) only as the **last** identifier entry, a tie-breaker after your own.

### The vulnerable item key

- **Key:** `u_si_correlation_id` + `u_vulnerability`, on both routes.
- **Stable id:** `u_source_record_id`. On the push it is `<CI key>|<finding key>`, for example
  `mdedeviceid:0000…0142|CVE-2099-10001`. In the hand-off database it is SecurityInsight's own record id (a GUID). Both
  never change for one finding on one CI; coalescing on either is safe within one route.

`u_vulnerability` is the finding's id as its source gives it: a CVE id, a Defender for Cloud assessment key, a Defender
security configuration id (`scid-…`) or a SecurityInsight rule id (`IDENTITY-…`, an attack path). It is unique per CI. A
longer id than 100 characters is cut to 59 characters plus `~` and a hash.

### Key-values and relations

- A key-value is identified by `u_si_correlation_id` + `u_source` + `u_key`.
- A relation is identified by `u_parent_correlation_id` + `u_child_object_id` + `u_relation_type`. The child is
  resolved by `u_child_correlation_id` when SecurityInsight hands the child over as a CI of its own, else by
  `u_child_object_id` (the child's Azure resource id) in the class of `u_child_class_hint`.

## The columns

Types are the SQL types of the views; on the push every value is text. "When known" columns are empty (SQL NULL) when no
source knows the value. The push leaves an empty value out of the row and lists the clearable ones in `u_si_cleared`
(see [Clear or unknown](data-out-contract#clear-or-unknown)). Every date and time is UTC; the push sends it as
`yyyy-MM-dd HH:mm:ss`. Every example is fictional.

### Configuration items (vImportCi, u_si_ci_import)

| Column | Type | Filled | Meaning | ServiceNow field | Example |
|---|---|---|---|---|---|
| `u_si_correlation_id` | nvarchar(400) | always | The CI key (see [Keys](#keys)) | Coalesce key; optional last IRE identifier | `mdedeviceid:0000…0142` |
| `u_id_source` | nvarchar(16) | always | `ledger` (stable) or `asset` (no ledger id yet; do not create a CI from it). Always `ledger` on the push | Not mapped; use in the transform | `ledger` |
| `u_class_hint` | nvarchar(16) | always | `device`, `azure-resource` or `identity` | Not mapped; chooses the class family | `device` |
| `u_proposed_class` | nvarchar(80) | when known | The class SecurityInsight proposes (push: `cmdb_ci_server`, `cmdb_ci_computer`, `cmdb_ci_comm`, `cmdb_ci_netgear`, `cmdb_ci_vm_instance`, `cmdb_ci_cloud_storage_account`, `cmdb_ci_cloud_database`, `cmdb_ci_cloud_webapp`, `sys_user`, `cmdb_ci_service_account`, else `cmdb_ci`) | `sys_class_name` of the IRE payload; your transform may override it | `cmdb_ci_computer` |
| `u_name` | nvarchar(400) | when known | The asset name | `name`; SecurityInsight as lowest-priority source | `DESKTOP-DEMO9` |
| `u_fqdn` | nvarchar(400) | when known | The fully qualified DNS name, lower case | `fqdn` | `desktop-demo9.contoso.test` |
| `u_dns_domain` | nvarchar(256) | when known | The DNS domain, taken from the FQDN | `dns_domain` | `contoso.test` |
| `u_serial_number` | nvarchar(128) | when known | The serial number from Defender, Intune or Azure (devices) | `serial_number` | `DEMO-SN-0077` |
| `u_mac_address` | nvarchar(64) | when known | A MAC address (devices; the push sends the first) | `mac_address` | `00-15-5d-00-01-42` |
| `u_object_id` | nvarchar(512) | when known | Hand-off database: an Azure VM's VM id (vmId), another Azure resource's resource id, or an identity's Entra object id. Push: the Azure resource id | `object_id` | `/subscriptions/…/vaults/kv-demo-secrets` |
| `u_azure_resource_id` | nvarchar(512) | when known | The Azure Resource Manager id, lower case | `u_azure_resource_id` (optional) | `/subscriptions/…/vaults/kv-demo-secrets` |
| `u_aad_device_id` | nvarchar(64) | when known | The Entra device id | `u_aad_device_id` (optional) | an Entra device id |
| `u_mde_device_id` | nvarchar(64) | when known | The Defender for Endpoint device id | `u_mde_device_id` (optional) | `0000…0d09` |
| `u_entra_object_id` | nvarchar(64) | when known | The Entra object id (identities, and devices where known) | `u_entra_object_id` (optional) | an Entra object id |
| `u_tier` | tinyint | when known | SecurityInsight's criticality tier: 0 is the most critical, 3 the least | `u_si_tier` (SecurityInsight authoritative) | `3` |
| `u_tier_reason` | nvarchar(512) | when known | Why the asset has that tier, in plain words | `u_si_tier_reason` (SecurityInsight authoritative) | `default tier for a client device with no owner` |
| `u_criticality` | nvarchar(32) | when known | The criticality SecurityInsight weighs risk with: your profile rule's override, else the CMDB record | Optional; low-priority source, or unmapped | `Medium` |
| `u_exposed_internet` | bit | when known | Exposed to the internet: 1 yes, 0 no | `u_si_exposed_internet` (SecurityInsight authoritative) | `0` |
| `u_last_seen` | datetime2(3) | when known | When SecurityInsight last saw the asset | `u_si_last_seen` (SecurityInsight authoritative) | `2026-10-06 04:11:00` |
| `u_source_run` | nvarchar(64) | when known | The SecurityInsight run the values come from (push: the sync's run; a `held` row keeps its last run) | `u_si_source_run` (traceability) | `demo-run-1006` |
| `u_run_time` | datetime2(3) | always | When SecurityInsight built this row (push: the start of the sync) | Not mapped | `2026-10-06 05:00:00` |
| `u_discovery_source` | nvarchar(32) | always | Always `SecurityInsight` | `discovery_source` of the IRE payload | `SecurityInsight` |
| `u_row_hash` | nvarchar(64) | always | A fingerprint of the row's content; it changes only when the content changes | Not mapped; change detection | 64 hex characters |
| `u_changed_at` | datetime2(3) | always | Hand-off database: when the row's content or state last changed (a plain re-sighting does not move it). Push: the start of the sync | Not mapped; the delta filter (hand-off database) | `2026-10-01 05:00:00` |
| `u_data_sensitivity` | nvarchar(32) | when known | The data sensitivity SecurityInsight weighs risk with: your profile rule's override, else the CMDB record | Optional; low-priority source, or unmapped | `Internal` |
| `u_si_state` | nvarchar(16) | when known | `active`, `not-seen` or `retired` (see [CI states](servicenow-records-and-states#ci-states)) | Your transform decides: a flag, a task, or `install_status` | `active` |
| `u_si_asset_type` | nvarchar(64) | when known | What the asset is, in SecurityInsight's one list (Workstation, Server, Database, Key vault, User, Service principal, …; Other, Unknown) | Optional; a filter or a note | `Workstation` |
| `u_si_asset_subtype` | nvarchar(64) | when known | The kind within the type (SQL Server, Domain controller, SQL Database, …; General) | Optional; picks the sub-CI SQL findings belong to | `Windows` |
| `u_owner` | nvarchar(256) | when known | The owner SecurityInsight knows from your CMDB services (database of your own only) | Optional, for example `owned_by` | `Jane Doe` |
| `u_owner_mail` | nvarchar(256) | when known | The owner's mail address (database of your own only) | Optional | `jane.doe@contoso.test` |
| `u_department` | nvarchar(128) | when known | The CI's department in SecurityInsight (database of your own only) | Optional, for example `department` | `Finance` |
| `u_batch_id` | nvarchar(64) | always | The batch (run) the row belongs to (database of your own only) | Not mapped | `demo-run-20261006` |
| `u_batch_time` | datetime2(3) | when known | When that batch completed (database of your own only) | Not mapped | `2026-10-06 05:03:00` |

The Pro database's view ends with `u_si_asset_subtype`; a hand-off database of your own adds the last five columns. In a
hand-off database of your own, `u_row_hash` also covers the owner and the department: compare hashes within one route
only. On the push, `u_row_hash` covers every content column, `u_last_seen` included, and none of the run and contract
columns.

**The push adds the contract's columns** after `u_si_asset_subtype`: `u_action`, `u_si_batch_id`, `u_si_cleared`,
`u_si_reason`, `u_si_replaces` (see [The contract's columns](#the-contracts-columns)). The push does not send `u_owner`,
`u_owner_mail`, `u_department`, `u_batch_id` or `u_batch_time`, and it sends devices, Azure resources and identities
(no public IP addresses).

### Tags (vImportCiKeyValue)

Hand-off database only.

| Column | Type | Filled | Meaning | ServiceNow field | Example |
|---|---|---|---|---|---|
| `u_si_correlation_id` | nvarchar(400) | always | The CI key | Resolves the CI | `mdedeviceid:0000…0142` |
| `u_key` | nvarchar(256) | always | The tag name | `cmdb_key_value.key` | `costcenter` |
| `u_value` | nvarchar(2000) | when known | The tag value; empty for a Defender tag | `cmdb_key_value.value` | `prod` |
| `u_source` | nvarchar(32) | always | `azure-tag` or `mde-tag` | Not mapped, or a key prefix | `mde-tag` |
| `u_state` | nvarchar(16) | always | `present`, or `removed` when the tag is gone | Delete or flag the key-value when removed | `present` |
| `u_changed_at` | datetime2(3) | always | When the row's content or state last changed | The delta filter | `2026-10-06 05:00:00` |
| `u_batch_id`, `u_batch_time` | | | As on the CI view (database of your own only) | Not mapped | |

### Relations (vImportCiRelation)

Hand-off database only.

| Column | Type | Filled | Meaning | ServiceNow field | Example |
|---|---|---|---|---|---|
| `u_parent_correlation_id` | nvarchar(400) | always | The CI key of the parent (the VM) | `cmdb_rel_ci.parent` | `azureresourceid:/subscriptions/…/vm-demo-app01` |
| `u_child_correlation_id` | nvarchar(400) | when known | The child's CI key, when SecurityInsight hands the child over as a CI | `cmdb_rel_ci.child` | empty |
| `u_child_object_id` | nvarchar(512) | always | The child's Azure resource id (disk, network interface, user-assigned identity) | `cmdb_rel_ci.child` through `object_id` | `/subscriptions/…/disks/vm-demo-app01-osdisk` |
| `u_child_class_hint` | nvarchar(80) | when known | The class SecurityInsight proposes for the child | The class to look the child up in | `cmdb_ci_storage_volume` |
| `u_relation_type` | nvarchar(80) | always | A `cmdb_rel_type` name: `Uses::Used by` (disks, identities) or `Contains::Contained by` (network interfaces) | `cmdb_rel_ci.type` by name | `Uses::Used by` |
| `u_source` | nvarchar(32) | always | `arm` (the Azure Resource Manager properties) | Not mapped | `arm` |
| `u_state` | nvarchar(16) | always | `present`, or `removed` when the relation is gone | Remove or flag the relation when removed | `present` |
| `u_changed_at` | datetime2(3) | always | When the row's content or state last changed | The delta filter | `2026-09-28 05:00:00` |
| `u_batch_id`, `u_batch_time` | | | As on the CI view (database of your own only) | Not mapped | |

A relation lands only when its child exists in your CMDB: SecurityInsight does not hand over disks and network
interfaces as CIs.

### Proposed CIs (vProposedCi)

Hand-off database only. Columns shared with `vImportCi` have the same meaning: `u_si_correlation_id`, `u_id_source`,
`u_class_hint`, `u_proposed_class`, `u_name`, `u_fqdn`, `u_serial_number`, `u_azure_resource_id`, `u_aad_device_id`,
`u_mde_device_id`, `u_entra_object_id`, `u_tier`, `u_last_seen`, `u_changed_at` (and `u_batch_id`, `u_batch_time` in a
database of your own). The report's own columns:

| Column | Type | Filled | Meaning | Example |
|---|---|---|---|---|
| `u_cmdb_match` | nvarchar(16) | always | `unmatched` or `unknown`; matched CIs are not in this report | `unmatched` |
| `u_evidence` | nvarchar(2000) | when known | The identifiers the correlation rests on | `key:asset; mde; fqdn` |
| `u_reason` | nvarchar(400) | always | Why the asset is listed, and whether its key is still provisional | `… its correlation id is provisional, so it must not be created from yet` |

Nothing is created from this report. Whether a class may be created is your IRE and transform decision.

### Vulnerable items (vImportVulnerableItem, u_si_vuln_import)

| Column | Type | Filled | Meaning | ServiceNow field | Example |
|---|---|---|---|---|---|
| `u_si_correlation_id` | nvarchar(400) | always | The CI key, the same as on the CI rows | Resolves `cmdb_ci` | `azureresourceid:/subscriptions/…/vm-demo-app01` |
| `u_class_hint` | nvarchar(16) | always | `device`, `azure-resource` or `identity` | Not mapped | `azure-resource` |
| `u_asset_name` | nvarchar(400) | when known | The asset the finding is on | Not mapped | `vm-demo-app01` |
| `u_cmdb_ci` | nvarchar(400) | when known | The CI's id in your CMDB when SecurityInsight knows it; usually empty | `cmdb_ci` when filled | empty |
| `u_vulnerability` | nvarchar(100) | always | The finding id (see [Keys](#keys)) | `vulnerability`: a CVE to `sn_vul_nvd_entry`, anything else to `sn_vul_third_party_entry` | `CVE-2099-10001` |
| `u_severity` | nvarchar(30) | when known | The finding's severity as SecurityInsight rates it (for example Critical, High, Medium, Low) | Optional | `Medium` |
| `u_state` | nvarchar(20) | always | `Open` or `Closed` | `state` | `Open` |
| `u_first_seen` | datetime2(0) | always | When SecurityInsight first reported the finding | `first_found` | `2026-09-12 04:20:00` |
| `u_last_seen` | datetime2(0) | always | When SecurityInsight last reported it | `last_found` | `2026-10-06 04:20:00` |
| `u_closed_at` | datetime2(0) | when known | When the record was closed; empty while open | Not mapped | `2026-10-06 05:02:00` |
| `u_close_reason` | nvarchar(400) | when known | Why it closed (see [Close reasons](servicenow-records-and-states#close-reasons)) | `u_si_close_reason` and your close code | `Remediated` |
| `u_absent_runs` | int | always | Complete runs in a row the finding was absent on an asset SecurityInsight saw | `u_si_absent_runs` (optional) | `0` |
| `u_source` | nvarchar(60) | always | Who opened the record: `SecurityInsight` | `u_si_source`; your ownership check | `SecurityInsight` |
| `u_source_record_id` | nvarchar(36) (view) / text (push) | always | The stable id (see [Keys](#keys)) | Coalesce key | `mdedeviceid:0000…0142|CVE-2099-10001` |
| `u_changed_at` | datetime2(0) | always | Hand-off database: when the record last changed (opened, refreshed, closed, reopened, or an absence counted). Push: the start of the sync | The delta filter (hand-off database) | `2026-10-06 05:02:00` |
| `u_finding_type` | nvarchar(32) | when known | `cve`, `azure-recommendation`, `endpoint-recommendation`, `identity`, `attack-path`, `exposure` or `recommendation` | Chooses the entry type | `cve` |
| `u_title` | nvarchar(400) | when known | The finding's name as its source gives it (often empty for a CVE) | Third-party entry name | `Machines should have vulnerability findings resolved` |
| `u_asset_id` | nvarchar(400) | when known | Hand-off database: the engine's own asset id the finding was reported on. Push: the CI key | Not mapped | `/subscriptions/…/vm-demo-app01` |
| `u_si_component` | nvarchar(32) | when known | OS, SQL, Network, Hardware, Browser, Office, Application or Other | The sub-CI: a SQL finding to the SQL instance, an OS finding to the server | `OS` |
| `u_si_servicenow_subci` | nvarchar(64) | when known | The sub-CI bucket: OS, SQL or Other by default; set per install on *Settings > ServiceNow > Sub-CI mapping* | Link the item under the CI's sub-CI of that name | `Other` |
| `u_si_os_family` | nvarchar(64) | when known | Windows, Linux, macOS, iOS, Android, Network OS, Other or Unknown | Filter or route | `Windows` |
| `u_si_patch_cycle` | nvarchar(64) | when known | In monthly cycle, Catch-up (older than 1 month), No fix available or Unknown | Filter or report | `In monthly cycle` |
| `u_si_batch_id` | nvarchar(100) | when known | The batch that last changed the record (Pro database view: the SQL vulnerability connector's batch) | Not mapped; the import rule | `run-1006:vuln-sql:sql-vuln` |

**The push adds** `u_row_hash` and `u_source_run`, then the contract's columns `u_action`, `u_si_batch_id`,
`u_si_cleared`, `u_si_reason` and `u_si_replaces`.

### The contract's columns

On every row of both push outputs:

| Column | Type | Filled | Meaning | Example |
|---|---|---|---|---|
| `u_action` | string | always | `new`, `update`, `close`, `reopen`, `held` or `out_of_scope` (see [Handling records and states](servicenow-records-and-states)) | `update` |
| `u_row_hash` | string | always | SHA-256 of the row's content columns: never the action, the batch, the clear marker, the reason, the replaced key or the run columns | 64 hex characters |
| `u_si_batch_id` | string | always | The batch that delivered the row, `<run id>:<output>` | `demo-run-1006:servicenow-ci` |
| `u_si_cleared` | string | when known | The clearable columns that are empty now, comma separated; never on a `held` row | `u_cmdb_ci,u_closed_at,u_close_reason` |
| `u_si_reason` | string | when known | Why the row is `held` or `out_of_scope` | `absent 1 complete run(s) - SecurityInsight closes a finding only after enough complete runs without it` |
| `u_si_replaces` | string | when known | The key this record replaces after a re-key; the old key gets no row of its own | `mdedeviceid:0000…0077` |
| `u_source_run` | string | when known | The run the values come from | `demo-run-1006` |

Create each column at least as long as the ServiceNow schema (JSON) of its table gives it.

### The staging status table (u_si_staging_status)

One table for both outputs. Each batch writes one row per state change. What your importer does with each state is on
[Knowing when a sync is complete](servicenow-sync-complete).

| Column | Label | Type | Max length | Meaning |
|---|---|---|---|---|
| `u_si_batch_id` | Batch id | String | 100 | The batch: `<SecurityInsight run id>:<output>`. The same value is on every data row of the batch and on each status row of the batch |
| `u_si_output` | Output | String | 40 | `servicenow-ci` or `servicenow-vulnerable-item` |
| `u_si_state` | State | String | 16 | `writing`, `complete`, `failed` or `held`; or `feedback` (information only, never a batch state) |
| `u_si_connector` | Connector | String | 100 | The SecurityInsight connector that sent the batch |
| `u_si_target_table` | Target staging table | String | 80 | The staging table the batch's data rows were sent to |
| `u_si_source_run` | Source run | String | 100 | The SecurityInsight run that sent the batch |
| `u_si_started_at` | Started at | Date/Time | 40 | When the batch started (UTC) |
| `u_si_finished_at` | Finished at | Date/Time | 40 | When the batch ended (UTC). Only on the end row |
| `u_si_batch_time` | Batch time | Date/Time | 40 | When the batch became complete (UTC). Only on a `complete` row |
| `u_si_planned_rows` | Planned rows | Integer | 40 | How many data rows the batch sends. On the end row |
| `u_si_sent_rows` | Sent rows | Integer | 40 | How many data rows ServiceNow accepted. Only on the end row |
| `u_si_failed_rows` | Failed rows | Integer | 40 | How many planned rows were not accepted or not sent. Only on the end row; 0 on `complete` |
| `u_si_import_set_ids` | Import sets | String | 4000 | The import sets of the data rows, comma separated. A long list ends with `(+N more)` |
| `u_si_reason` | Reason | String | 1000 | Why the batch ended as it did, in plain words |
| `u_si_version` | SecurityInsight version | String | 64 | The SecurityInsight version that sent the batch |
| `u_si_contract_version` | Contract version | String | 16 | The data contract's version (`1`) |
| `u_si_mode` | Mode | String | 16 | `live`, `resync` (import it like live) or `test` (never import it) |
| `u_si_new_rows` | New rows | Integer | 40 | Rows with `u_action` = `new`. Only on the end row |
| `u_si_update_rows` | Update rows | Integer | 40 | Rows with `u_action` = `update`. Only on the end row |
| `u_si_close_rows` | Close rows | Integer | 40 | Rows with `u_action` = `close`. Only on the end row |
| `u_si_reopen_rows` | Reopen rows | Integer | 40 | Rows with `u_action` = `reopen`. Only on the end row |
| `u_si_held_rows` | Held rows | Integer | 40 | Records held in this batch: rows with `u_action` = `held`, plus first-time records not sent yet. Only on the end row |
| `u_si_out_of_scope_rows` | Out of scope rows | Integer | 40 | Rows with `u_action` = `out_of_scope`. Only on the end row |
| `u_si_import_inserted` | Import: inserted | Integer | 40 | Your import's result, as SecurityInsight read it back: rows inserted. Only on a `feedback` row |
| `u_si_import_updated` | Import: updated | Integer | 40 | Rows updated. Only on a `feedback` row |
| `u_si_import_ignored` | Import: ignored | Integer | 40 | Rows ignored, including rows your IRE *onBefore* script handed over and ignored. Only on a `feedback` row |
| `u_si_import_skipped` | Import: skipped | Integer | 40 | Rows skipped. Only on a `feedback` row |
| `u_si_import_errors` | Import: errors | Integer | 40 | Rows in error. More than 0 raises a SecurityInsight issue. Only on a `feedback` row |
| `u_si_import_pending` | Import: pending | Integer | 40 | Rows not transformed yet when SecurityInsight read the result. Only on a `feedback` row |

### Batches (vImportBatch)

**In the Pro database**, the batches of the CMDB SQL connector (`u_output` = `servicenow-ci`) and of the SQL
vulnerability connector (`u_output` = `servicenow-vulnerable-item`):

| Column | Type | Meaning |
|---|---|---|
| `u_si_batch_id`, `u_batch_id` | nvarchar(100) | The batch (the same value in both) |
| `u_output` | nvarchar(40) | `servicenow-ci` or `servicenow-vulnerable-item` |
| `u_connector` | nvarchar(100) | The SecurityInsight connector that wrote it |
| `u_state` | nvarchar(16) | `writing`, `complete`, `held` or `failed` |
| `u_started_at`, `u_finished_at` | datetime2(3) | When the batch started and ended |
| `u_batch_time` | datetime2(3) | When it became complete; only on `complete` |
| `u_reason` | nvarchar(1000) | Why the batch ended as it did |
| `u_si_contract_version`, `u_si_mode` | nvarchar(16) | The contract version and the mode |
| `u_new_rows`, `u_update_rows`, `u_close_rows`, `u_reopen_rows`, `u_held_rows`, `u_out_of_scope_rows` | int | The counts per action |
| `u_landed_rows` | int | The records the batch wrote |

**In a hand-off database of your own:**

| Column | Type | Filled | Meaning |
|---|---|---|---|
| `u_batch_id` | nvarchar(64) | always | The batch (the run) |
| `u_connector` | nvarchar(64) | always | The SecurityInsight connector that wrote it |
| `u_state` | nvarchar(16) | always | `writing`, `complete`, `held` or `failed` |
| `u_started_at` | datetime2(3) | always | When the batch started |
| `u_batch_time` | datetime2(3) | when known | When it completed |
| `u_ci_count` | int | always | CIs in the batch, seen and no longer seen |
| `u_key_value_count` | int | always | Key-value rows |
| `u_relation_count` | int | always | Relation rows |
| `u_new_cis` | int | always | CIs that were not in the previous batch |
| `u_changed_cis` | int | always | CIs whose content changed since the previous batch |
| `u_disappeared_cis` | int | always | Active CIs of the previous batch this run did not see (carried with their state, not dropped) |
| `u_previous_batch_id` | nvarchar(64) | when known | The complete batch this one was compared with |
| `u_reason` | nvarchar(1000) | when known | The counts of a complete batch, or why a batch was held |

Verified against SecurityInsight 3.0.0.202610261957 on 2026-10-27.
