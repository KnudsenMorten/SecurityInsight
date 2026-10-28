# CMDB and ServiceNow

SecurityInsight Pro works with your CMDB in two directions:

- **In:** your business services, their criticality and data sensitivity, and which assets belong to them. This
  weights the risk score (see [Weighted risk](weighted-risk)) and places assets in departments.
- **Out:** SecurityInsight's view of every configuration item (CI) and every vulnerable item, handed to ServiceNow
  through ServiceNow's own standard import. Your ServiceNow rules make every change.

This page is for the SecurityInsight admin. The ServiceNow pages below are written for your ServiceNow administrators
and developers.

## Your CMDB in SecurityInsight

Open **Assets & services > CMDB**. One CMDB source is **authoritative** at a time:

| Source | How it works |
|---|---|
| **SecurityInsight** | You add services on the CMDB page. Each gets a number (SVC-0001, SVC-0002, …) that is never reused, and you link assets to them. |
| **CMDB.csv** | A CSV in the CMDB.csv format, uploaded on the page or read from a path on a schedule. Columns: `cmdbID;cmdbName;DataSensitivity;Criticality;Owner;OwnerMail`, plus `Environment`, `Description`, `Department` and any of your own. |
| **ServiceNow** | Services and their members are pulled from ServiceNow by the scheduled CMDB import through the ServiceNow connector. |

With an external source, the CMDB page and the service map show the services read-only; you change them in the source
and they arrive with its next import. To change the source, choose **Switch the CMDB source**. The review says exactly
what happens before anything is saved.

A file is checked **line by line** before anything is written. If one line is wrong, nothing is written and the page
lists the lines to fix. An incomplete read from ServiceNow is never imported, so a service is retired only when
ServiceNow no longer has it.

**Upgrading from 2.2?** Use **Import your v2.2 CMDB.csv (once)**. Each service gets a number and keeps its cmdbID. An
optional second file links assets (`cmdbID;AssetName` or `cmdbID;AssetKey`).

## Your profile rules win over the CMDB record

An asset-profile rule can map assets to a CMDB service (`cmdbId`) and can also set `cmdbName`, `cmdbCriticality` or
`cmdbDataSensitivity`. A value set in the rule is an **override**: it says these assets differ from what the CMDB record
says. For example, the "Active Directory" service is *Confidential*, but your domain controllers are *Restricted*.

The order, field by field:

1. a matched rule that sets the field;
2. the CMDB record (the service the rule's `cmdbId` points to, or a CI matched by identity);
3. nothing: the field stays empty.

The profile tables record where each value came from: `CmdbNameSource`, `CmdbCriticalitySource` and
`CmdbDataSensitivitySource` (`rule:<rule id>`, `cmdb`, or empty). The weighted risk score, the Pro CI table and the
ServiceNow hand-off all use the effective value.

## Data sensitivity

Data sensitivity says how sensitive the data on an asset is (for example *Confidential* or *Restricted*). Together with
criticality, it multiplies the risk score, so the same finding ranks higher on a payroll server than on a sandbox.

SecurityInsight hands the effective value to ServiceNow as `u_data_sensitivity`. Mapping it is your choice: map it to the
field your CMDB keeps data sensitivity in, with SecurityInsight as a low-priority source, or leave it unmapped and keep
your CMDB's own value.

## Handing data to ServiceNow

SecurityInsight never writes ServiceNow CIs or vulnerable items. It fills staging (the views of a hand-off database, or
Import Set staging tables through the ServiceNow data-out connector), and your ServiceNow import, transform maps, IRE and
Vulnerability Response make every change. Every target follows one contract: the same keys, values and batch states, and
one rule, act only on a complete batch. The pages below describe it for your ServiceNow team:

| Page | What it covers |
|---|---|
| [The SecurityInsight data contract](data-out-contract) | The one contract for ServiceNow and the SQL connectors: columns, actions, batch states, clear marker, versioning |
| [ServiceNow integration overview](servicenow-overview) | What SecurityInsight sends, the two routes, the scoped subset, the flow |
| [ServiceNow staging tables and columns](servicenow-columns) | Every table and every column, the keys |
| [Handling records and states](servicenow-records-and-states) | What the importer does with every record, action and state |
| [Knowing when a sync is complete](servicenow-sync-complete) | The staging status table, what a sync sends, retention, volumes and timing |
| [Setting up ServiceNow for SecurityInsight](servicenow-setup) | Tables, column mapping, transform maps, example scripts, roles, credential, scope |
| [Testing with the SecurityInsight test pack](servicenow-test-pack) | Build and approve the integration before it goes live |
| [ServiceNow troubleshooting and FAQ](servicenow-troubleshooting) | Every message, its cause and fix; common questions |

To set it up in SecurityInsight:

- **Hand-off database:** the Pro database carries the views; for a database of your own, add a connector on
  **Configuration > Connectors > Setup** with kind **sql** and direction **cmdb**, and give its `server` and
  `database`.
- **ServiceNow push:** on **Configuration > Connectors > Setup**, set up one ServiceNow connector with direction
  **data-out**: its instance URL, how it signs in (an API key, or a user and a password), **Verify**, and **Switch on**.
  Set each output's table on *Data out: ServiceNow CI Import Set table* and *Data out: ServiceNow vulnerable item Import
  Set table*, and the staging status table on *Data out: ServiceNow staging status table* (`u_si_staging_status` when not
  set). Send the section **For your ServiceNow team** to your ServiceNow team.
- **Full resync and test batch:** the card **ServiceNow: one route** on the same page offers **Full resync...** (the next
  sync sends every record in scope as new) and **Send a test batch...** (the next sync first sends at most 5 rows per
  output in a batch the importer never imports). Each proposes the setting *SI_DataOut_ServiceNowRequest* on the settings
  page: review it there and save. The next sync carries it out once.
- **Scope:** on **Configuration > Connectors > Scope**, choose what each target receives: *CMDB connector (ServiceNow)*
  for the CIs and *Vulnerability connector (ServiceNow)* for the vulnerable items of the push.

## Assets SecurityInsight no longer sees

An asset SecurityInsight has not seen for 8 days is **not seen**. Once it has not been seen for longer than the grace
period of its kind, it is **retired**. The grace period is 30 days by default and can be set per kind on
**Configuration > Settings** (client PCs, servers, service principals, users, Azure VMs, other Azure resources).
**Assets & services > CMDB > Not seen anymore** lists the assets in their grace period with their open findings; an
Admin can retire one early, with a reason. Both changes are recorded in the audit log, and an asset that is seen again
is active again. SecurityInsight hands the state to ServiceNow and never retires or deletes a CI there (see
[Handling records and states](servicenow-records-and-states)).

## ServiceNow credentials

Credentials are never stored in a file or on a web page. They live in the install's Key Vault, and connectors refer to
them by secret **name**. The database route needs no ServiceNow credential at all.

Verified against SecurityInsight 3.0.0.202610261957 on 2026-10-27.

