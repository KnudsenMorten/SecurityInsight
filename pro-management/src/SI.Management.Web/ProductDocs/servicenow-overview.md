# ServiceNow integration overview

This page is for your ServiceNow administrators and developers. It says what SecurityInsight sends to ServiceNow, how it
gets there, which part of it you receive, and where the other ServiceNow pages fit:

| Page | What it answers |
|---|---|
| [The SecurityInsight data contract](data-out-contract) | The one contract every target follows: keys, actions, values, batch states, the import rule |
| [ServiceNow staging tables and columns](servicenow-columns) | Every table and every column: type, when filled, meaning, mapping, example |
| [Handling records and states](servicenow-records-and-states) | What your importer does with every record, action and state |
| [Knowing when a sync is complete](servicenow-sync-complete) | The staging status table, when to import, retention and sizing |
| [Setting up ServiceNow for SecurityInsight](servicenow-setup) | Tables, column mapping, transform maps, scripts, roles, credential, scope |
| [Testing with the SecurityInsight test pack](servicenow-test-pack) | How to build and approve the integration before it goes live |
| [ServiceNow troubleshooting and FAQ](servicenow-troubleshooting) | Every message SecurityInsight gives, its cause and its fix; common questions |

## What SecurityInsight sends

| Object | One row per | What it carries |
|---|---|---|
| **Configuration items (CIs)** | CI | Devices, Azure resources and Entra identities: the identifiers your identification rules match on (name, FQDN, serial number, MAC address, Azure ids, Entra ids), SecurityInsight's security attributes (tier, tier reason, internet exposure, last seen) and the CI's state in SecurityInsight |
| **Vulnerable items** | CI and finding | Every security finding on a CI: CVEs, Defender for Cloud recommendations, Defender security configurations, identity findings, attack paths and exposures; open, or closed with the reason |
| **Tags** | CI, source and key | Azure tags and Defender machine tags, present or removed |
| **Relations** | parent, child and type | A VM's disks, network interfaces and user-assigned identities, present or removed |
| **Proposed CIs** | CI | Assets no CMDB CI is known to match, with the evidence. A report for your CMDB team |

CIs and vulnerable items travel through both routes. Tags, relations and proposed CIs travel through the hand-off
database only.

## What SecurityInsight never does

SecurityInsight fills **staging only**: rows in the views of a hand-off database, or rows in Import Set staging tables on
your instance. Your import sets, transform maps (or IntegrationHub ETL), Identification and Reconciliation Engine (IRE)
rules and Vulnerability Response transform own every record and make every change. SecurityInsight never:

- writes a `cmdb_ci*`, `sn_vul*` or any other record table (the push refuses every table that is not an import set
  table);
- creates, retires or deletes a CI, or sets `install_status`;
- deletes anything in ServiceNow, including the staging rows it inserted;
- touches a record it did not send;
- reads your transform maps.

## The two routes

| | ServiceNow push | Hand-off database |
|---|---|---|
| **How the data moves** | The ServiceNow data-out connector posts rows to your Import Set staging tables through the Import Set API | Your MID Server reads SQL views through a JDBC data source into an import set |
| **ServiceNow credential in SecurityInsight** | An API key, or a user and a password, in your Key Vault | None |
| **Objects** | CIs (output *ServiceNow CI hand-off*), vulnerable items (output *ServiceNow vulnerable items*) | CIs, tags, relations, proposed CIs, vulnerable items, batches |
| **Which rows** | The full current scoped state, every sync, each row with `u_action` | Every row, every time; you filter on `u_changed_at` |
| **When to import** | When the batch's `complete` row is in the staging status table | When the batch is complete in `snowstage.vImportBatch` |

Both routes follow [the SecurityInsight data contract](data-out-contract): one key per record, one set of values, one
batch rule. Choose the **hand-off database** when your ServiceNow already reads SQL through a MID Server, when you want
tags, relations and the proposed CIs report, or when SecurityInsight must hold no ServiceNow credential. Choose the
**ServiceNow push** when there is no MID Server path to the database.

The push is set up on **Configuration > Connectors > Setup**: one ServiceNow connector with direction **data-out** feeds
both outputs. The card **ServiceNow: one route** on that page states the route and offers **Full resync...** and **Send a
test batch...**.

## What every sync sends

Every sync of the push sends, per output, **one batch** with the full current state of the records in scope:

1. a `writing` row in the staging status table;
2. every record in scope, each row with `u_action` (`new`, `update`, `close`, `reopen`, `held` or `out_of_scope`),
   `u_row_hash`, `u_si_batch_id`, `u_si_cleared`, `u_si_reason`, `u_si_replaces` and `u_source_run`;
3. the end row: `complete`, `failed` or `held`, with the counts per action.

The CIs are sent before the vulnerable items. An unchanged record arrives as `update` with the same `u_row_hash`, so your
transform can skip it. Import a batch only when its `complete` row exists.

## The scoped subset

You do not have to receive everything. On **Configuration > Connectors > Scope**, your SecurityInsight admin sets what
each target receives, for example only Critical and High risk ratings, or only devices and Azure resources:

| Scope | What it limits |
|---|---|
| CMDB connector (ServiceNow) | The CIs of the push: asset kinds and tiers |
| Vulnerability connector (ServiceNow) | The vulnerable items of the push: risk rating, severity, security domain, tier and more |
| CMDB connector (SQL), Vulnerability connector (SQL) | The SQL connectors |

The values and rules are on [Setting up ServiceNow for SecurityInsight](servicenow-setup#scope-settings). What you see
when a record leaves the scope:

- **A vulnerable item** gets one row with `u_action` = `out_of_scope`, `u_state` = `Closed` and `u_close_reason` =
  `Out of scope`, never as remediated. It reopens when it comes back in scope.
- **A CI** gets one row with `u_action` = `out_of_scope` and keeps its state. No more rows follow while it is out of
  scope. It is never a deletion or a retirement.

## The flow

```text
 SecurityInsight                                       ServiceNow (your rules)
 ---------------                                       -----------------------
 1. Collect: Defender, Entra, Azure, ...
 2. Correlate assets into CIs, run Risk Analysis
 3. Deliver (daily pipeline, Deliver stage)
    |
    +-- ServiceNow push, one batch per output -------> Import Set staging tables
    |      writing row -> data rows -> end row            u_si_ci_import, u_si_vuln_import
    |      (insertMultiple, 200 rows per call)            + staging status table u_si_staging_status
    |                                                      |
    +-- hand-off database (snowstage views) ---------> JDBC data source on your MID Server
           batch: writing -> complete                      |
                                                           v
                                         your import, when the batch is complete
                                                           |
                                                           v
                                         Transform maps / IntegrationHub ETL
                                                           |
                                         +-----------------+------------------+
                                         v                                    v
                               IRE (discovery source              Vulnerability Response
                               SecurityInsight) -> CIs            -> vulnerable items
```

1. **Collect.** SecurityInsight reads its sources and correlates the assets into CIs, each with one stable key.
2. **Analyze.** Risk Analysis finds the security findings on every CI.
3. **Deliver.** In the Deliver stage of the daily pipeline (see [The daily pipeline](pipeline)), SecurityInsight
   writes the hand-off views and pushes one batch per output.
4. **Import.** When a batch is complete, your import reads its rows, your transform maps hand CIs to IRE with the
   discovery source `SecurityInsight`, and your Vulnerability Response transform creates, updates, reopens and closes the
   vulnerable items.

## One key per record

`u_si_correlation_id` is SecurityInsight's key for one CI, and the CI rows and the vulnerability rows carry the same
key. A vulnerable item's key is `u_si_correlation_id` + `u_vulnerability`. In IRE, keep your own identification rules
first, and use `u_si_correlation_id` at most as the last identifier entry. See
[ServiceNow staging tables and columns](servicenow-columns#keys).

Verified against SecurityInsight 3.0.0.202610261957 on 2026-10-27.
