# Handling records and states

This page tells your importer what to do with every record SecurityInsight sends, for every action and every state. The
columns are on [ServiceNow staging tables and columns](servicenow-columns); the rules every target shares are on
[The SecurityInsight data contract](data-out-contract).

## Rules for every record

1. **Import only complete batches.** Act on the rows of a batch only when its `complete` row exists (see
   [Knowing when a sync is complete](servicenow-sync-complete)). Never import a `test` batch.
2. **A missing row is never a deletion.** SecurityInsight never asks you to delete anything. A record changes only on a
   row that says so: `u_action` on the push, `u_si_state`, `u_state` and `u_close_reason` in the hand-off database.
3. **Every row stands alone.** Coalesce on the keys, so a row sent twice updates the same record and never creates a
   second one.
4. **`held` means change nothing.** SecurityInsight cannot confirm or close the record in this batch; `u_si_reason` says
   why.
5. **Only Remediated is a fix.** Map every other close reason to a close code that is not "fixed".
6. **Clear only what is listed.** An empty column listed in `u_si_cleared` is cleared; any other empty column is unknown:
   keep your value.
7. **Touch only what SecurityInsight sent.** Skip a vulnerable item whose `u_source` is not `SecurityInsight`, and let
   your reconciliation rules decide which CI attributes SecurityInsight may set.

## The actions on the push

Every sync sends the full scoped state of each output, one row per record, each with `u_action`. The action comes from
what the record is in SecurityInsight now and what your instance last received for it in a complete batch:

| `u_action` | When | What your importer does |
|---|---|---|
| `new` | First time in a complete batch, or after a full resync | Create the record (if your rules allow), or update it if it exists |
| `update` | The record is active or open, as your instance last received it | Update it; skip it when `u_row_hash` equals the hash you keep |
| `close` | The CI is retired, or the finding is closed (sent on every sync while the record stays closed) | Close it with `u_close_reason`. Already closed, or never created: nothing |
| `reopen` | It was closed, retired, out of scope or gone, and is active or open again | Reopen it |
| `held` | SecurityInsight cannot confirm or close it in this batch | Change nothing |
| `out_of_scope` | It left the scope this target receives (sent once) | A vulnerable item: close it as not fixed (`Out of scope`). A CI: keep it; no more rows follow while it is out of scope |

The full table of the action per case is on [The SecurityInsight data contract](data-out-contract#every-sync-sends-the-full-state).

## Configuration items

### CI decision table

| `u_action` | `u_si_state` | Your CMDB | What the importer does |
|---|---|---|---|
| `new` | `active` or `not-seen` | IRE finds no CI | Create only if your rules allow creation for that class; otherwise it stays unmatched (the hand-off database lists it in the proposed CIs report) |
| `new` | `active` or `not-seen` | IRE matches a CI | Update the attributes SecurityInsight is authoritative for (tier, tier reason, exposure, last seen, source run, state); fill the others as the lowest-priority source |
| `update` | `active` | A matched CI | Update as above. Skip the row when `u_row_hash` and `u_si_state` equal what you keep |
| `update` | `not-seen` | A matched CI | Record the state (a flag, a field `u_si_state`). Do not retire or delete. Keep the last `u_last_seen` |
| `close` | `retired` | A matched CI | Your lifecycle decision: a flag, a task for your CMDB team, or `install_status`. SecurityInsight never deletes it |
| `close` | `retired` | No CI | Nothing |
| `reopen` | `active` or `not-seen` | A matched CI | Clear the flag or reverse your retirement step; update as above |
| `held` | any | A matched CI | Change nothing |
| `out_of_scope` | any | A matched CI | Change nothing, or flag that SecurityInsight no longer sends it. Not a deletion, not a retirement |
| any | any | `u_si_replaces` is set | Find the CI by the key in `u_si_replaces` and move it to the row's `u_si_correlation_id`, instead of creating a new CI |

In the hand-off database there is no `u_action`: the row's `u_si_state` is the state, and `u_changed_at` moves when it
changes. An asset-keyed row there (`u_id_source` = `asset`) creates nothing: the key changes once when the identity
ledger mints the CI's id, and the row arrives again with `ledger`.

### CI states

The CI's lifecycle in SecurityInsight (`u_si_state`):

```text
               seen again                         seen again
        +--------------------+          +---------------------------+
        v                    |          v                           |
   +--------+   not seen for     +----------+   not seen past the   +---------+
   | active | -----------------> | not-seen | --------------------> | retired |
   +--------+   the seen window  +----------+   grace period, or    +---------+
        |       (default 8 days)                 an Admin retires        ^
        |                                                                |
        +----------------------- an Admin retires early -----------------+
```

- **Seen window:** *CI seen-window*, 8 days by default.
- **Grace period:** 30 days by default, set per kind on **Configuration > Settings** (*Days before an unseen asset is
  retired*: client PCs, servers, service principals, users, Azure virtual machines, other Azure resources).
- A kind of asset whose source could not be read in a run is frozen: none of its CIs changes state in that run.

What your CMDB holds for a CI, by the push's actions:

```text
   (no record) --new--> [ active / not-seen ] --close--> [ retired ]
                          ^   |   ^                          |
                          |   |   +--------reopen------------+
                          |   |        (seen again)
                          |   | out_of_scope (once)
                          |   v
                          +- [ out of scope ]
                 reopen (back in scope)

   update and held keep the CI where it is. A CI that leaves SecurityInsight's
   data gets one held row, then no more rows; your CI stays as it is.
```

## Vulnerable items

### Decision table on the push

| `u_action` | `u_state` | Your record | What the importer does |
|---|---|---|---|
| `new` | `Open` | None | Create the vulnerable item, linked to the CI whose key is `u_si_correlation_id` |
| `new` | `Open` | Exists (a re-sent row, or a full resync) | Update it: coalescing makes this safe |
| `update` | `Open` | Open | Update `last_found` and the mapped attributes; skip it when `u_row_hash` equals the hash you keep |
| `update` | `Open` | Closed by an engineer | **Reopen it**, with the reason: SecurityInsight still sees the finding |
| `reopen` | `Open` | Closed | Reopen it |
| `close` | `Closed` | Open | Close it with the close code of `u_close_reason`: `Remediated` as fixed, every other reason as not fixed |
| `close` | `Closed` | Closed, or none | Nothing |
| `held` | `Open` or `Closed` | Any | **Change nothing.** You may note `u_si_reason` |
| `out_of_scope` | `Closed` | Open | Close it as not fixed, reason `Out of scope` |
| `out_of_scope` | `Closed` | Closed, or none | Nothing |
| any | any | `u_si_replaces` is set | Find the record by `u_si_replaces` (`<old CI key>|<finding key>`) and move it to the row's key |

### Decision table in the hand-off database

| `u_state` | `u_close_reason` | Your record | What the importer does |
|---|---|---|---|
| `Open` | | None | Create the vulnerable item, linked to the CI whose key is `u_si_correlation_id` |
| `Open` | | Open | Update `last_found` and the attributes you map |
| `Open` | | Closed | Reopen it (an engineer's close is reopened while SecurityInsight still reports the finding) |
| `Closed` | `Remediated` | Open | Close it as fixed |
| `Closed` | any other reason | Open | Close it with a close code that is not "fixed" (see [Close reasons](#close-reasons)) |
| `Closed` | any | Closed | Nothing, or update the close notes |
| `Closed` | any | None | Nothing: SecurityInsight closed a record you never created |
| `Open` with `u_absent_runs` above 0 | | Open | Keep it open: SecurityInsight counts the absences and closes it only when they are enough |

### Vulnerable item states

```text
                    finding first reported
                              |  new
                              v
                         +--------+   update: still reported
              +--------> |  Open  | <----+
              |          +--------+      |
   reopen:    |            |   |  |      | held: absence still counting,
   reported   |  close:    |   |  +------+ CI not delivered, report incomplete,
   again, or  |  absent    |   |           disabled, or left SI's data (once)
   back in    |  enough    |   |
   scope      |  complete  |   | out_of_scope (once):
              |  runs, or  |   | Closed, reason Out of scope
              |  a reason  v   v
              |       +--------+
              +------ | Closed |  with u_close_reason
                      +--------+
```

### Close reasons

| Reason | Meaning | Close code |
|---|---|---|
| `Remediated` | Absent for the required complete runs in a row on an asset SecurityInsight saw | Fixed |
| `AssetRetired` | The CI was retired. Reopens if the asset comes back | Not fixed (for example retired) |
| `NoLongerMonitored` | The asset is excluded from assessment | Not fixed |
| `Out of scope` | Still reported, but outside the scope this target receives. Reopens when it comes back in scope | Not fixed |
| `Duplicate` | A second record of a finding that already has one; the other record carries it on | Not fixed (duplicate) |
| `Report changed` | The report that found it changed its query or is no longer run | Not fixed |
| `Linked` | Linked into another finding of the same CI, which carries it on | Not fixed |
| `Rekeyed` | The same finding is reported under another key | Not fixed |
| `ClosedByEngineer` | Closed by a person in SecurityInsight | Your choice |
| `No longer reported by SecurityInsight` | Closed without the asset's state known | Not fixed |

### When SecurityInsight closes

1. **Remediated** needs all of: a complete run; the asset seen in this run with its own data; and the finding absent for
   *Runs before a vulnerability closes* complete runs in a row (default 2). While the count runs, the item is `held`
   (`u_si_reason`: *absent N complete run(s)*).
2. **AssetRetired** when the CI is retired.
3. **Out of scope**, **Linked** and **Duplicate** at once, because the finding is still reported.
4. **An incomplete run closes nothing.** A report that could not complete in the newest run holds its findings.
5. **The SQL vulnerability connector's safety limits.** An empty result closes nothing. When fewer than half of the open
   records are still reported (*Vulnerabilities: share that must still be reported*, 0.5), nothing closes. When the
   closes would be more than 10% of the open records (*Vulnerability close limit (% of open records)*; *Vulnerability
   close limit (number of records)*, 0 = no number limit), they are held for an Admin to release once on *Operations >
   Guards (safety checks)*. Closes a fresh Defender assessment corroborates, out-of-scope, linked and retired-asset closes
   are not counted by the limit.

SecurityInsight never closes a record because your instance says it is closed.

### What held means

A **held** row asks you to change nothing. On the push it arrives with `u_action` = `held`; in the hand-off database the
record stays as it is. Why a record is held, and until when:

| `u_si_reason` says | Until |
|---|---|
| *absent N complete run(s)* | The next complete run that counts the absence: it closes as Remediated, or the finding is reported again |
| *the account or device is disabled and left out by a setting* | It is enabled again, or the setting changes |
| *the report that found it could not complete in the newest run* | The next complete run of that report |
| *its CI … is not delivered in a complete batch yet* | The CI's batch is complete. A vulnerable item your instance never had is not sent until then, and is counted in `u_si_held_rows` |
| *the finding has no CI key* | It is reported on a CI |
| *not in SecurityInsight's data any more* | Sent once; then no more rows. Your record stays as it is |

The SQL vulnerability connector (hand-off database) also holds a record while the asset was not seen in this run, while
the CI is `not-seen`, while the collection scope leaves the asset out, while every source of the asset failed, while a
twin record waits for its re-key, and while a run is halted by a safety limit.

## Tags

Hand-off database only.

### Tag decision table

| `u_state` | Your CMDB | What the importer does |
|---|---|---|
| `present` | No `cmdb_key_value` row for the CI, source and key | Insert it (`key`, `value`; a Defender tag has no value) |
| `present` | A row with another value | Update the value |
| `present` | A row you removed or flagged earlier | Restore it: the tag came back |
| `removed` | A row | Delete it or flag it, as your CMDB keeps history |
| `removed` | No row | Nothing |

A tag's row is identified by `u_si_correlation_id`, `u_source` and `u_key`.

### Tag states

```text
   (none) --- tag found ---> +---------+   gone from the source    +---------+
                             | present | ------------------------> | removed |
                             +---------+ <------------------------ +---------+
                                           back in the source
```

## Relations

Hand-off database only.

### Relation decision table

| `u_state` | The child in your CMDB | What the importer does |
|---|---|---|
| `present` | Found by `u_child_correlation_id`, else by `u_child_object_id` in the class of `u_child_class_hint` | Create or keep the `cmdb_rel_ci` with the type `u_relation_type` |
| `present` | Not found | Skip it and log it. SecurityInsight does not hand disks and network interfaces over as CIs; the relation lands once another source created the child |
| `removed` | Found | Remove or flag the relation |
| `removed` | Not found | Nothing |

### Relation states

```text
   (none) --- in the VM's    +---------+   gone from the VM's      +---------+
              properties --> | present | ------------------------> | removed |
                             +---------+ <------------------------ +---------+
                                           back on the VM
```

## Proposed CIs

Hand-off database only.

### Proposed CI decision table

| `u_cmdb_match` | `u_id_source` | What your CMDB team does |
|---|---|---|
| `unmatched` | `ledger` | Review the evidence (`u_evidence`). Create the CI by your own process, or extend your identification rules so it matches |
| `unknown` | `ledger` | SecurityInsight does not know whether a CMDB CI matches. Check it before you act |
| any | `asset` | Do not create from it: `u_reason` says the key is provisional |
| no row | | The CI matches a CMDB CI now, or is no longer proposed. Nothing to do |

The proposed CIs are a report. SecurityInsight creates nothing from it, and an importer never needs to read it.

### Proposed CI states

```text
   asset no CMDB CI is known to match
                 |
                 v
          +-----------+   a CMDB CI matches   +-----------------+
          | unmatched | --------------------> | not in the      |
          | / unknown |                       | report          |
          +-----------+                       +-----------------+

   u_id_source asset -> ledger: the row's key changes once, when the
   identity ledger mints the CI's id.
```

## Change, hash and duplicates

### The row hash

`u_row_hash` is a fingerprint of a row's content. Keep it on the record (for example in a field `u_si_row_hash`) and
skip a row whose hash equals the one you keep. On the push, every record arrives every sync, so without this check your
transform touches every record on every sync; `u_row_hash` there covers every content column, `u_last_seen` included,
and never the action, the batch or the run. Skip only `update` rows on the hash; never skip a `close`, `reopen` or
`out_of_scope` row. In the hand-off database, the CI hash covers the identifiers, tier, tier
reason, criticality, exposure, data sensitivity, asset type and evidence, not `u_last_seen`; a hand-off database of your
own also hashes the owner and the department. Compare hashes within one route only.

### Re-sent rows

Every row can arrive more than once: every sync sends the full state, a failed call is tried again, and the rows of a
batch that did not complete go again in the next batch. Coalescing on the keys makes this safe.

### Duplicates

- **CIs:** one row per CI key per batch.
- **Vulnerable items:** one row per CI and finding per batch. When a finding had two records, SecurityInsight keeps the
  older one and closes the other as `Duplicate`.

### Order inside a sync

- The CI batch is sent before the vulnerable item batch. A vulnerable item whose CI is not delivered in a complete batch
  is held (see [What held means](#what-held-means)).
- Rows go in calls of 200, one after the other. Each call is one import set; ServiceNow transforms them asynchronously
  by default, so do not rely on the order in which import sets transform. Wait for the `complete` row, then import the
  batch.

Verified against SecurityInsight 3.0.0.202610261957 on 2026-10-27.
