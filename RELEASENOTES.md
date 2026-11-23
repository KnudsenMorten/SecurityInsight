# SecurityInsight release notes

<!-- install lines: from setup/install-parameters.json (installer) -->
**Install SecurityInsight Community** in Azure Cloud Shell (PowerShell) with two lines: line 1 downloads the installer
from the latest public release, line 2 runs it. Every other setting is a parameter of line 2 with its default.

```powershell
Invoke-WebRequest https://github.com/KnudsenMorten/SecurityInsight/releases/latest/download/Install-SecurityInsight.ps1 -OutFile Install-SecurityInsight.ps1
./Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>'
```

SecurityInsight Pro and the Pro trial install from invardia.com, never from GitHub: start at
[invardia.com/trial](https://invardia.com/trial/), and your installation page there gives your two lines.
<!-- /install lines -->

## v3.1.43.5 — the Azure collection no longer waits silently on Defender for Cloud

### Fixes
- **Each Defender for Cloud read now has a time limit.** On large installations the Azure collection could wait
  an hour or more without a word in the log. Every retry is now logged and a progress line appears at least every
  minute. A read that still gives up is marked as unknown for that subscription, never shown as nothing found.

## v3.1.43.4 — security update of the base images

### Fixes
- **SecurityInsight's containers are rebuilt on Microsoft's newest base images.** Microsoft published security
  fixes for the .NET and Ubuntu base images SecurityInsight builds on; this release moves to them.

## v3.1.43.3 — security update of the base images

### Fixes
- **SecurityInsight's containers are rebuilt on Microsoft's newest base images.** Microsoft published security
  fixes for the .NET and Ubuntu base images SecurityInsight builds on; this release moves to them.

## v3.1.43 — AI switched off is off everywhere, and a run never fails because the AI connection is missing

### Fixes
- **AI off wins over every AI switch.** With AI switched off for your installation, no engine, no AI summary and no tier
  catalog build uses AI, whatever their own switches say.
- **No failed run without an AI connection.** When the AI summary is on but the Azure OpenAI connection is not set, the
  run says so once and builds the Top 50 lists without the summary. Before, a complete Risk Analysis run ended failed.
- **Support can switch AI off.** Support can switch the AI summary and each engine's AI switch off for your installation
  through the nightly update, never on.

## v3.1.42 — the attack-path reports to Azure complete at the largest installations

### New
- **Alert at the AI daily limit.** When the AI daily limit is reached, Invardia receives an alert as well as the warning in
  the run log, so support sees it at once.

### Fixes
- **Attack-path reports use the stored graph.** The two reports on devices with high-severity vulnerabilities that allow
  lateral movement to Azure answer every part from the graph SecurityInsight stores once per run, so they complete at the
  largest installations. A part that cannot use the stored graph is said as a warning in the run log.
- With AI switched off, the update leaves the Azure OpenAI roles of the engine and web identities alone and does not
  mention them.

## v3.1.41 — AI is off unless you switch it on, asks only about what changed, and stops at a daily limit

### New
- **AI daily limit.** *Configuration > Settings > AI* has a daily limit in tokens next to the AI switch, with what it
  costs per day. At the limit SecurityInsight sends no more AI requests that day and tells you once.
- **AI asks only about what changed.** With AI switched on, an asset is asked about only when the facts that decide its
  answer changed, 25 assets per request, with only those facts. Raw device data is never sent.
- **AI is off by default.** Every AI feature is off until a person switches it on in Settings, in both editions.
- **A stuck step no longer holds an update.** A pipeline step that has written nothing for far longer than it usually takes
  is stopped and reported, and the update follows when the run has ended. A step that still writes progress is never stopped.

### Fixes
- The update's first step, pointing itself at the new release, works again instead of waiting until the end of the update.
- An AI request is tried at most twice, and a request the service refuses is not sent again.
- Every deck the tools build opens in PowerPoint.
## v3.1.40 — every change is checked against the signed sign-in of the person who made it

### New
- **Signed changes.** The engine checks the signed sign-in of the person behind every web app change before it acts.
  SecurityInsight first only observes; once a SuperAdmin adopts the configuration on *Configuration > Signed requests*,
  an unverified change is held and explained.
- **Access and History in both editions.** *Configuration > Access* and *Configuration > History* are part of the
  Community edition too. Every security control is the same in both editions.
- **Narrower database rights, step by step.** Support can narrow each component's database rights to exactly its job,
  through the nightly update: first a plan that changes nothing, then the change, read back, and a way back.

## v3.1.39 — Defender for Cloud from two sources; long data syncs finish

### New
- **Defender for Cloud read from two sources.** SecurityInsight reads your Defender for Cloud findings both from Azure
  Resource Graph and from Defender for Cloud itself, per subscription, and combines them. Findings that one source stops
  returning are still read from the other.
- **Support can load a licence edition.** Support can request a licence edition for your installation, or switch back to
  the previous licence, through the nightly update. Only a licence signed for your own tenant is ever installed.

### Fixes
- **New vulnerabilities counted correctly in data health.** Data health counts a vulnerability that Defender reports on a
  device after a collection as new, not as missing from SecurityInsight.
- **Long data syncs finish.** A long data sync keeps a valid sign-in to the database for its whole run, and a short service
  fault in Log Analytics is retried instead of ending the step.
- **Every failed run names its cause.** Each failed run reports a stable code that says what happened.
- **Collection picker and Findings page.** The collection picker shows each run's time and rows only; the Findings page
  lists only the runs whose findings are kept.
- **ServiceNow checks of the task tables.** They check the connection, the table and its columns, without a false warning.
## v3.1.38 — support can switch off a report whose data source your licence does not include

### New
- **Reports switched off by support.** When a report's data source is not part of your licence, support can switch that
  report off for you, the same way an Admin does under Reports. The change is in the change log with who asked and why.

## v3.1.37 — the Findings page lists only the runs whose findings are kept

### Fixes
- **Findings lists only kept runs.** The Findings page's collection picker lists only the runs whose findings are kept (the
  newest 3 by default), like every view.

## v3.1.36 — the collection picker no longer says older data

### Fixes
- **Collection picker without older data.** The collection picker shows each run's time and rows only; Run health >
  Reports lists every report of the run.

## v3.1.35 — task views open from every task report; no older-data note on the pages

### Fixes
- **Task views open from the task reports.** Opening Tasks per asset or Task findings from a task report (a product, a
  group, an action) shows the tasks with their detected paths.
- **No older-data note on the pages.** When some reports of a run show older data, the pages no longer show a note
  about it; the collection picker still says "older data", and Run health > Reports lists every report.
## v3.1.34 — task views show where to fix; one filter; Verify on the ServiceNow connector works again

### Fixes
- **Detected paths in the task views.** Tasks per asset and Task findings show where the product was found on the
  asset (the disk paths from Microsoft Defender), so you know where it needs fixing. Every task column is shown by default.
- **One filter on the task views.** Tasks per asset and Task findings filter with the grid's own filter, like every other
  view; the task reports' filter is one compact row. The note about reports with older data is one slim line.
- **Verify on the ServiceNow connector page starts the check again.** SecurityInsight's pipeline job starts it within 5
  minutes and the result shows on the page.
## v3.1.33 — security update of the base images; the earlier sign-in component removed

### Security
- **SecurityInsight's containers are rebuilt on Microsoft's newest base images.** Microsoft published security fixes
  for the .NET base images SecurityInsight builds on; this release moves the engine, the updater, the web app and the
  MCP server to them.
- **The earlier sign-in component is no longer part of the release.** Every installation signs in with Microsoft's
  built-in sign-in; the separate sign-in component that came before it is no longer carried, built or offered.

## v3.1.32 — remediation tasks for IT operations, linked everywhere; complete attack-path reports at large installations

### New

- **Task reports for IT operations** (Remediations > Task reports), each with export and a click-through to the tasks
  behind a row:
  - **Deploy once, fix many**: one row per action across all assets -- the assets it covers (and how many are Tier 0/1),
    its highest severity and risk rating, the CVEs it removes and the tool that fits (patch tool, software deployment,
    policy, Azure, manual). Actions on many assets come first, ranked by the risk they remove.
  - **By product** (and version), **by any dimension** (tool, kind, owner, department, IT service, OS, age and more),
    **actions no mass deployment fits**, and **opened and fixed per week**.
  - Every report, Tasks per asset and Task findings filter by IT service (from the CMDB link), OS and OS version, device
    type, subscription, resource group, location, tool, kind, tier, owner, department, age, and by the findings' severity,
    risk rating, security domain, category and subcategory. A task matches when one of its findings matches, and it is
    then counted over those findings.
  - Tasks now show their highest risk rating next to their highest severity.
- **Management report, chapter 6 "Remediation"**: open tasks and the assets they cover, opened and closed as fixed since the
  last report, the oldest open task, open work per tool, and the **Top 50 actions** -- in full on the page, in the PDF and in
  the mail, and on five slides in the presentation pack.
- **Tasks linked everywhere**: the asset page and the CI page show the asset's remediation tasks (open first, every task
  reachable); a finding's page lists the task it belongs to; an asset name on the task pages, the findings list and a
  finding's page opens the asset page with its linked objects.

### Fixed

- **The CI page lists every finding.** Its two findings lists stopped at 500 without saying so; they now page through all
  findings, and the headings give the true totals (open and overdue counted over every finding).
- **Attack-path reports complete at the largest installations.** The two reports on devices with high-severity
  vulnerabilities that allow lateral movement to Azure read Microsoft's attack-path data once per run and work out the
  paths in SecurityInsight's own database, instead of asking for the whole graph again for each part of the report. The rows
  are the same as before; a read that fails keeps the report's last complete result, and nothing of it closes.
- The asset filter on Tasks per asset matches the asset exactly (it also matched assets whose name only started the same).

## v3.1.31 — the task's own columns in the Tasks view

### Changed

- **Remediations > Tasks per asset shows the task's own columns.** Paths, Closed, Reopened, Highest weighted risk and
  Security domain are shown by default, and they stand with the other vulnerability columns: the
  weighted risk next to the risk score, the security domain next to the tier, the paths next to the application, the closed
  date and reopen count with the other dates. A layout you saved yourself stays as you saved it; reset the layout to get the
  new default.

## v3.1.30 — remediation tasks per asset, ready for ServiceNow

### New

- **Remediation tasks, on by default.** SI now groups findings into tasks an admin can act on: one per vulnerability per
  asset (split by software version), one per application for a library bundled inside other programs (all its paths
  listed, in full), and one per configuration setting. Page: Remediations > Tasks per asset (a task's findings open from its row), with export.
  Department owners see the tasks of their own findings.
  - A task closes as "fixed" only when its findings are proven gone; a version change with the finding still there closes
    it as "task changed".
  - Two new ServiceNow outputs (tasks and task findings) are on by default. They send once their Import Set table names
    are entered on the ServiceNow data-out connector page; until then they are "not set up" (no error, nothing sent).
    Installations that already send to ServiceNow get them switched on by the update, read back and recorded in the
    change log; an admin can switch them off.
  - The task build runs per owner range, so its memory and database load stay small at any size (tempdb at 600,000
    findings: 220 MB instead of 4 GB), with exactly the same tasks as before. Values are kept in full: no task name, key,
    application or CVE is cut.
- **ServiceNow connector page.** The two new task tables can be entered next to the vulnerable-item table. "Verify table
  schema" checks all tables: each column present, missing, too short or the wrong type, and which new columns can be
  switched on.
- **ServiceNow grouping fields.** The vulnerable-item output can carry 14 more fields (security domain, category,
  subcategory, report, risk score and rating, tier, fix KB, affected vendor and product, security grouping, exception).
  They ship OFF and are switched on per installation (Connectors > Fields sent, or by support), once ServiceNow has the
  fields. A field ServiceNow lacks is left out with one warning per run; the rest of the row still goes.
- **ServiceNow task outputs consistent with vulnerable items.** Same date format (UTC), the same clear marker (a reopened
  task clears its close date and reason), and the same columns and row fingerprint on the REST push and the SQL hand-off
  views. Long values reach the SQL route whole.
- **Attack-path reports more reliable.** Each slice is sized to half of the query back end's own time limit (Defender,
  Log Analytics and the Sentinel data lake each have their own); a timed-out key query now splits the slice like any other
  timeout; a report is only marked complete when its row count was read after the query. The Top 50 report pass now
  accepts columns written in another case.
- **Where software was found.** Every software finding keeps the full path on every drive and the application it belongs
  to, so a wrong conclusion (for example web-server files in a user folder on a file server) can be seen and corrected.
- **False positive on this server.** An Admin can mark a software detection as a false positive for one server (Assets &
  services > Assets (CIs) > Software detection exceptions), with a reason, audited and reversible.
- **Tenant name search from SI's own data.** People and group pickers search what SI already collected, with no result
  limit; a name not yet collected is looked up by the engine. The pickers no longer read the directory from the web app.
- **Plainer warning mails.** Data-quality notices now say what happened, whether anything was lost, and whether you need to
  do anything.
- **Faster and leaner at large installations.** The vulnerability step and the software-evidence join use a fixed amount of
  memory whatever the size; every record gets the same decision and ServiceNow receives the same as before.

### Known

- The finding key on a task link and the CI lifecycle are stored at up to 256 characters (real finding ids are at most
  100), and a finding's title at up to 1,000; both are to be widened together with the finding lifecycle.
## v3.1.29 — faster nightly runs at large installations

### Performance
- **The data sync reads each finding once.** Its derived passes work from one read of every finding instead of reading the
  stored data again in each pass; the results are identical, column for column.
- **The vulnerability step skips work it never used.** Findings on assets that are frozen, retired or not seen are no
  longer read into its two passes; their records get exactly the same decisions as before.
- **The vulnerability step does its per-finding work compiled.** The same rules decide every value; the bulk work around
  them runs as compiled code.

### Fixes
- **A long attack-path report shows its progress.** While it splits slow requests, the run keeps reporting progress, so it
  is no longer flagged as not moving.

### Security
- **New installations deploy the MCP server closed to the internet.** It answers only inside the installation; running
  the installation again never reopens it.
## v3.1.28 — only the images in use are kept

### Security
- **The image clean-up keeps only what runs.** After an update, the installation's container registry keeps only the
  images its jobs and apps run (and their signatures); earlier images are removed. A rollback is a newer fixed release.
- **Unused SecurityInsight repositories are emptied.** A repository SecurityInsight created that nothing runs from any
  more is emptied; repositories SecurityInsight did not create are never touched. When what runs cannot be read, nothing
  is deleted.

## v3.1.27 — the right rights, set by the update itself

### Security
- **Each SecurityInsight identity holds exactly the rights it needs.** Rights it no longer uses are removed by the update;
  rare, powerful rights are given only on demand by the support partner, never kept; the rights normal operation needs
  are granted at setup and read back.
- **The web app reads no Azure details itself.** The environment report's facts are gathered by the update and shown by
  the web app from the database, so the internet-facing web app needs no read right on your resource group.
- **Settings are changed only by the update.** A support partner sets a value on the update job; the update applies it,
  reads it back and records it -- never a direct database change.
## v3.1.26.1 — tighter Key Vault rights for the web app

### Security
- **The web app keeps no earlier Key Vault right.** The update removes the right to write secrets that the web app held
  before it handed secrets to the updater, read back.
## v3.1.26 — AI works with the newest models, and the switch leaves nothing behind

### Fixes
- **AI works with the newest Azure OpenAI models.** SecurityInsight now asks for answers the way current models expect
  (and adjusts once by itself when a model refuses a setting), so the AI summary and the web chat work with the
  newest models too.
- **The earlier sign-in leaves nothing behind.** Once an installation runs Microsoft's sign-in and keeps its sign-in
  keys in its own storage, the update removes the earlier sign-in's images and keys -- each step read back.
- **Scripts are published unsigned, always.** A dormant signing path is removed, and a check keeps it out for good.

### Under the hood
- Every release hands its approved list of rights to the support partner, so its checks always compare against the
  current list.
## v3.1.25 — signed in all day, and updates that finish in one go

### Security
- **Signed in all day without a new sign-in.** The web app now checks that every sign-in token is still valid, and the
  page renews the sign-in by itself before it runs out -- so a working day stays signed in, and an expired token is
  never accepted.
- **The sign-in check proves itself at start.** Each time the web app starts, it runs Microsoft's own token check on
  test tokens (one valid, four invalid). If that check does not hold, the new version is not taken into use.
- **SecurityInsight never gives itself rights on your AI.** A leftover way to grant the web chat its Azure OpenAI role
  is gone; the role is yours (or your support partner's) to give.

### Fixes
- **An update finishes in one go.** Steps that come with a new version (for example the sign-in and AI settings) now
  run in that version during the same update, instead of one scheduled update later.
- **Microsoft's sign-in switch prepares its own storage**, so the one right it needs can be given at the first ask.
- **A short network or "busy" hiccup during an update is reported as such**, not as a failure, when nothing changed
  and SecurityInsight stays healthy on the version before.
- **The unused AI key setting is removed** once AI runs without a key and no key is kept anywhere.
- **The documentation's version is reported**, so a support partner sees when it falls behind.
## v3.1.24.1 — the switch to Microsoft's sign-in finishes on large installations

### Fixes
- **The sign-in keys move off the Key Vault even when the web app is busy.** Right after the switch, the web app can
  still be applying its previous change; the move now waits for it and tries again, instead of leaving the keys in
  the Key Vault until a later update.
- **No wrong advice about the sign-in.** An installation on Microsoft's sign-in is never told to turn it off for the
  earlier sign-in front.
## v3.1.24 — AI without a key

### Security
- **AI works without a key.** With AI turned on and the Azure OpenAI endpoint and deployment set, SecurityInsight signs
  in to your Azure OpenAI resource with its own identities: the engines, the AI summary and the web chat. No key is
  stored or needed. SecurityInsight's identities need the role "Cognitive Services OpenAI User" on that resource; you or
  your support partner give it, and SecurityInsight never gives itself a role. Each update checks the role and says
  plainly what is missing.
- **A key from an older setup is only a fallback.** An installation that still has a key keeps working: the key is used
  only when the sign-in with SecurityInsight's own identity is refused, and the run log says once which way AI signed in.

### Fixes
- **The web chat follows your AI settings.** Each update gives the web chat the endpoint and deployment from your
  settings, and takes them away when AI is turned off. The web app restarts only when a value changed.
- **The engines follow your AI settings.** Each update gives the engines the endpoint and deployment from your settings,
  so a change on the Settings page reaches them without a new install.
- **Get Started no longer asks for a key.** The AI step is done when AI is on and the endpoint and deployment are set.
  The key field stays only for older setups and is marked optional.
- **The Azure OpenAI check script starts after a sign-in.** The downloaded check script no longer stops at once when it
  is run after signing in with an application.

## v3.1.23.1 — new MCP clients find Microsoft's sign-in by themselves

### Security
- **A new MCP client finds Microsoft's sign-in by itself.** The MCP server tells an MCP client where to sign in and what
  to ask for, so a new client connects without extra setup. Besides its health answer, only this sign-in information is
  open, and neither carries any data.
- **The MCP server answers people only.** A person signs in as themselves with the SecurityInsight MCP permission, and
  sees only what their SecurityInsight role allows. An application signed in as itself is no longer answered: a tool
  that used the MCP server that way now signs in as a person.

### Fixes
- **Stop and update never stops a run it could not read.** It stops a run only when it has read that run's record and
  the record names the running run. When the record cannot be read, nothing is stopped and nothing is started, and it
  says how to go on: start the update on its own (it waits for a running run by itself), or try again once the record
  can be read.
## v3.1.23 — every public address behind Microsoft's sign-in

### Security
- **The MCP server is behind Microsoft's sign-in too.** It answers only requests that carry a valid Microsoft sign-in,
  and still checks the token and the person's role itself. Only its health answer is open, and it carries no data.
- **Every public address is checked.** Each update lists every part of the installation that is reachable from the
  internet and reports any that is not behind Microsoft's sign-in.
- **The web app verifies who signed in.** With Microsoft's sign-in, the person comes only from a sign-in token the web
  app verifies itself (signature, tenant, audience and age), never from a header alone.
- **No Key Vault access for the web app.** After the switch, the web app keeps its sign-in keys in its own storage and
  gives up its Key Vault rights, each step read back.
- **The updater only reads group membership.** It no longer holds any right to change group memberships; it checks that
  the database job's membership is in place and, when it is not, names the support step.
- **Leftovers of the earlier sign-in are removed.** After the switch, its settings and its database tables are removed
  and read back; anything else it left is reported.

### Fixes
- **A refused save says who refused it**: SecurityInsight's own message as given, or that the sign-in layer refused it
  and the page should be reloaded.

## v3.1.22 — saving works with Microsoft's sign-in

### Fixes
- **Saving a form works with Microsoft's sign-in.** With Microsoft's built-in sign-in switched on, a form save was
  refused. The web app now lets the browser send its own address to SecurityInsight only (never to another site), which
  Microsoft's protection against forged requests needs, so every save works again.

## v3.1.21 — Microsoft's sign-in switches on reliably

### Fixes
- **Switching on Microsoft's sign-in waits until the web app is ready.** When an update has just rolled out a new web
  app version, the switch now waits for it to finish (and tries again while Azure says another change is in progress)
  instead of stopping. Nothing was left half-done before; the switch simply did not happen.
- **The account picker is always shown**, also when an installation sets its own sign-in parameters.

## v3.1.20 — choose the account at every sign-in

### Security fixes
- **Microsoft's sign-in always asks which account to use.** With Microsoft's built-in sign-in, the account picker is
  always shown, so an admin can sign in with a separate admin account instead of the account the browser is already
  signed in with. The no-access pages offer "Sign in with another account".

## v3.1.19 — Microsoft's built-in sign-in can protect the web app

### Security features
- **Microsoft's own sign-in in front of the web app.** The web app can sit behind the built-in authentication of Azure
  Container Apps: every visitor signs in with Microsoft Entra before reaching SecurityInsight, the organisation's
  Conditional Access applies, and no password or secret is stored -- the web app's managed identity proves itself to
  Entra. Sessions last a fixed eight hours. It is switched on per installation by the support partner; until then the
  current sign-in stays as it is. When it is switched on, every step is read back and anything that does not check out
  is put back as it was.

### Fixes
- **Group access keeps working with the new sign-in.** SecurityInsight reads each person's groups itself, so access
  given to a group works the same with Microsoft's sign-in.

## v3.1.18 — security update: the parts reachable from the internet hold only the rights they need

### Security fixes
- **The web app and the MCP server hold only the rights for their own data.** Their identities keep the rights they use
  for their own work (reading the install's data and jobs, their sign-in keys) and nothing that manages jobs, other
  identities or rights. Every update checks this and removes anything more, read back. The web app setup and the mail
  setup no longer give these identities more.
- **Until the next version**, Run now, stopping a run, schedule changes, template releases and the "send now" of a mail on
  the web pages show a message instead of acting. The scheduled pipeline runs as usual, and queued mails go out with the
  next scheduled mail run. The next version brings these actions back in a way that needs no such rights.

### Fixes
- **A short network fault to the database is tried again.** When the connection to the database fails for a moment while
  it is being set up, SecurityInsight tries again after a short wait instead of stopping the run.

## v3.1.17 — every mail goes once, records never move back, and What's new in the web app

### New features
- **What's new in the web app.** Help > What's new shows what every SecurityInsight version brought, newest first, in
  plain words, with a "New" mark after an update until you open it. The same text is on invardia.com and, for the
  Community edition, in WHATSNEW.md on GitHub.

- **Security updates install within the hour.** When a security update of the images SecurityInsight runs on is released,
  the install takes it within the hour, without waiting for the nightly update: it builds the patched images in its own
  registry and swaps them in, part by part. A running job is never stopped for it: it finishes on its image, the next one
  starts on the new one. The old images are removed once a job has run successfully on the new one, and the install
  reports which images it runs.

### Fixes
- **Data correlation waits while a data table is still taking a new field.** It used to stop the run, and every step
  after it was skipped. It now reads again for a few minutes, and the run goes on as usual.
- **A mail that should go once goes once.** The Risk Analysis mail goes at most once per pipeline run, and the daily
  summary mail at most once a day, also when a step runs a second time. The mail queues (exemptions, reports, sign-in
  and governance mails) are claimed before each send, so two senders never send the same mail. A mail that waits
  because the send right could not be checked keeps its tries, as before.
- **A record's collection time never moves back.** When two collections of the same kind write at once, the device or
  identity record that a newer collection wrote is always the one kept; the log counts the records an older collection
  left alone.
- **A collection's saved verdict on its source data is removed together with the collection**, and the verdicts that
  were left behind by older versions are removed too.

## v3.1.16.1 — security update of the sign-in page

### Fixes
- **The sign-in page in front of the web app is rebuilt on Microsoft's newest security updates.** Microsoft published
  security fixes for the .NET components the sign-in page uses; this release moves to them.

## v3.1.16 — only complete collections are kept, updates stay alive, and a held install is never quiet

### Fixes
- **Only complete collections count toward the collections that are kept.** A collection built on incomplete source
  data never pushes a complete one out of the kept history any more. At most one such collection is kept, the newest,
  for diagnosis; it is never shown or sent. Every other one is removed, and the log names each removed collection and
  why its run was not complete. The published collection is always kept.
- **A held install is never quiet.** When data out is held because the newest collection was built on incomplete source
  data, the status SecurityInsight reports says so on every run and every hour: since when it is held, and which
  complete collection is the newest.
- **An update stays alive during long database work.** A long database statement of an update now reports that the
  update is still working, every 5 minutes, in the log. A working update is no longer stopped as if it had hung. A real
  hang is still stopped.
- **The updater moves itself to the new version right after the engine jobs are healthy**, not at the very end of the
  update. An update that is stopped later no longer leaves the updater on the old version. A move that fails is tried
  again at the end of the update.
- **A step whose container never started is started again; a step that did run is never started twice.** SecurityInsight
  now waits until Azure's own start events have arrived (they can be up to 15 minutes late) before it decides, and a
  step that is still running is followed instead of started a second time.
- **The pipeline status shows a finished run as finished**, also while an update runs right after it.
- **Mail waits when the send right cannot be checked.** When Microsoft does not answer the check of the shared
  mailbox's send right, the mail is held and keeps its tries; the next run checks again.
- **The end of an update's log now arrives**, and the image clean-up's result line shows the count the registry ends at.
- **The identity collection's quick user count works again.** It was refused on every run, so the collection fell back
  to a slower full read.

## v3.1.15 — a collection goes out only when its run finished every step

### Fixes
- **Nothing is sent out from a run in which a collection step failed.** A collection is now trusted only when the run that
  built it finished every step it is built on. Until now a source step that failed in the run — for example a collection
  whose container could not start — still left the previous successful result as the newest one, so the collection
  looked complete. Now such a collection is held: nothing is sent from it to ServiceNow or the workbooks, what they have
  stays, and the next complete run sends what changed. The log names the step that did not finish.
- **A re-run from a later step is judged by the run it continues.** When a run is started again from a later step, each
  step it did not run is judged by how that step ended in the run being continued, so a failure there still holds the
  collection.
- A step that is switched off, or a step running beside Risk Analysis that it does not read, never holds a collection.

## v3.1.14 — data out checks the very collection it sends

### Fixes
- **Data out now checks the collection it actually sends.** Each run records, together with its own collection, whether
  it was built on complete source data, and the data sync checks that record for the collection it is about to send —
  not whatever source run happens to be newest when the sync starts. A collection built on incomplete source data is
  held: nothing is sent from it to ServiceNow or the workbooks, what they have stays, and the next complete run sends
  what changed. When a collection carries no record (a run from an older version), the source runs decide, as before.
- **A held data out is now a warning in the log**, with the collection's time and why it was held, so it is never only
  an information line.

## v3.1.13 — only trusted data goes out, device sign-ins are read on every run, and old images are cleaned up safely

### Fixes
- **The privileged sign-ins of the devices are read on every run.** A device that a Tier 0, 1 or 2 account signs in to
  takes that tier.
- **A problem with one tier source no longer makes the whole run incomplete.** Only that one value is shown as unknown on
  the devices, with a code that says why; everything else of the run is complete and goes on as usual.
- **Nothing is sent out from a collection that was built on incomplete source data** — not to ServiceNow, not to the
  workbooks. What they have stays as it is, and the next complete run sends what changed.
- **The clean-up of old container images stays alive during long work and says what it does as it goes**: it records what
  it keeps before it deletes anything, and writes each repository's plan and result at once.

### Changed
- **Every installation keeps the findings of its newest 3 complete runs** — the newest and the 2 before it — instead of 7.
  Older runs keep their totals for the trends. Each run whose findings are removed is named in the log as it goes.

## v3.1.12 — a week of history, a steadier attack-path analysis and a faster end of Risk Analysis

### What's new
- **Every installation keeps the findings of its newest 7 runs**, so What changed and the history pages go back a week.
  The number is a setting. When the database is 70 % full or more, SecurityInsight keeps one run fewer each time (never
  fewer than 2) and says so, instead of filling the database.

### Fixes
- **A query part that Microsoft's Advanced Hunting keeps timing out on is split into smaller parts** instead of being
  asked again the same way, so a heavy attack-path report completes instead of leaving parts unread.
- **The Summary view is built for every collection the web app shows**, also when one preparation step failed the night
  before; it no longer says "not built yet" for the collection you are looking at.
- **The end of a large Risk Analysis is much faster**: the Top 50 lists and key figures are worked out in the database
  instead of reading every result row one at a time (hours at the largest installations). The results are the same.
## v3.1.11 — old images are cleaned up, the patched .NET packages, and a complete security pack

### What's new
- **The installation's own registry keeps only the current release and the one before.** After an update has been
  checked healthy, the updater deletes the older images from the installation's own registry and says per repository
  what was deleted and what is left. A rollback of one release uses the image that is kept; an older one is rebuilt.
  Nothing is deleted when the update did not end healthy or when the previous release is not known.

### Fixes
- **The web app's .NET packages carry Microsoft's November security update (10.0.15).**
- **The security pack names the published support scripts**, with their rights and changes.
## v3.1.10 — a device takes the tier of its most privileged logon, mails name their environment, one path for Community and Pro

### What's new
- **A device takes the tier of the most privileged account that signs in to it.** When a Tier 0, 1 or 2 account signs
  in to a device, the device is classified at that tier; otherwise it keeps the tier of its most frequent user. Accounts
  in the HR and finance groups make their devices Tier 2, so those devices are patched before Tier 3 devices. The check
  is incremental: each run reads only the sign-ins since the last run, and a device's first privileged sign-in is
  enough, so it scales to very large fleets. Each run's log says how many devices were raised and by which kind of
  sign-in; an optional setting lets you leave out named accounts.
- **Every mail names its environment.** The subject and first line start with the environment's kind and name, and the
  body names the tenant, so a mail from one installation is never mistaken for another.
- **Community and Pro install, run and update the same way.** Both editions use the same installer, updater, jobs,
  support access and maintenance tools; only the licensed features differ. A setting is marked Pro only when it belongs
  to a licensed feature.
- **A Community installation can be connected to Invardia, on its own choice.** The installer asks "Connect this
  install to Invardia: health reports + updates on request". Without a yes, a Community installation sends nothing that
  identifies its tenant or its installation.

### Fixes
- **The health report shows that the database statistics are fresh**, with the time of the last refresh.
- **A long step's progress time is kept when the clocks of two services differ by a few seconds**; before, the progress
  could disappear and the step look stalled.
- **The management presentation's file name is always one Windows can save.** A title with characters such as `:` or
  `?` no longer reaches the attachment's name.
## v3.1.9 — a faster end of the CI build, and clearer logs

### Fixes
- **The end of the CI build is much faster on large installations.** Marking every configuration item as built read
  ever more records the further it got, and read each record's document again; on a large installation it took many
  hours. Each part now reads only its own records, and each document at most once.
- **The privilege tier classifier's log says "AI" only when AI is used.** With the daily downloaded catalog (the
  default) the log now says which catalog version gave the tiers; nothing suggests an AI request that was not made.
- **A Risk Analysis warning that every data path failed now names the path that really failed last**, with its
  error, and a failed count used only to time a completeness check no longer raises a warning.
## v3.1.8 — long steps say how far they are, and a ready path for base image security updates

### What's new
- **Every long step shows its progress.** The comparison of vulnerability findings, its paging and writing passes, and
  the CI build's final "mark as built" pass now report how far they are (for example "mark built 140,000 of 310,000")
  at least every few minutes. A long night no longer looks stuck to you or to support.
- **Base image security updates are released the same day.** When Microsoft publishes a patched base image, the
  release is built from the previous version's code on the new image only, tested, and released to every ring; if it
  fails, the installations switch back to the image they ran before.
## v3.1.7 — a current privilege tier catalog for every installation, and runs that never wait on one report

### What's new
- **Every installation tiers roles and permissions from a current catalog.** Every installation now downloads the daily classified catalog by default -- checked before it is used, and
  the last good one is kept if a download fails. Building the catalog yourself with AI stays possible as an opt-in when AI
  integration is on (it adds AI cost); it is never switched on by itself. The catalog's Tier 0 / Tier 1 boundary is fixed by
  reviewed rules, so a permission's tier does not change from day to day.
- **The tier classifier never holds a night.** If the catalog cannot be read or built, the night goes on with the last
  known classification (on a first run, with the shipped catalog) and says so.
- **A break-glass account is always Tier 0**, whatever roles it holds right now.
- **With AI integration on, built-in roles follow your own classification** instead of the shipped list.

### Fixes
- **One report's retries no longer hold a whole run.** When Microsoft's advanced hunting keeps timing out on one heavy
  report, its recovery gets a time budget (90 minutes, a setting); after that, the parts not read are reported as unknown
  -- never as resolved -- the run goes on, and the next run reads that report again in full.
- **The data-health check reports even when runs do not finish**: when its last report is more than a day old and the
  installation is idle, it runs on its own on the stored data.
- **The "bucket count jump" warning only appears on a real jump** in a report's size, not after a query change.
- **An old collection job from before the collection was split is removed after 14 days** even if it was once started
  by hand.
## v3.1.6 — the data-health check never reports a false loss

### Fixes
- **The data-health check no longer reports missing vulnerability data that is not missing.** On some installations the
  check compared Defender's findings with a short read of the stored findings and reported the difference as an anomaly
  ("last cycle was anomalous"), although the findings were stored. It now reads the stored findings of the same
  collection the devices were sampled from, picks each device's record the same way every time, checks that it read
  everything and reads again if not. If it still cannot read everything, that cycle says "the check could not read all
  stored findings -- not a data anomaly" instead of reporting a loss. A real loss is still reported.
## v3.1.5 — the sign-in front of Pro installs on the .NET security update

### Fixes
- **The sign-in front of SecurityInsight Pro carries Microsoft's November security update of .NET (10.0.15).**
## v3.1.4 — rights given through PIM groups are followed at any depth, and a faster device page

### Fixes
- **SecurityInsight follows rights given through PIM groups, at any depth.** When access is delegated in steps --
  a person is eligible in a group that holds no role itself, and that group is eligible in the groups that hold the
  roles -- SecurityInsight follows every step: eligible and active, member and owner, nested to any depth. It covers Entra roles
  (tenant-wide and administrative-unit scoped) and Azure roles at every scope, including roles a group is only eligible
  for, and it applies to workload identities as well as people. The profile shows the way, for example
  "Group <role group> (can activate via <persona group>) -> <role>". A read that fails is reported as unknown, never as
  "no roles". No new permission is needed.
- **Opening a device is fast.** The device page's history and its open items read only that device's rows, so on a
  large installation the page opens in seconds instead of 20-30 seconds.
- **The Community sign-in page is up to date.**
## v3.1.3 — security update of the .NET runtime

### Fixes
- **The web app, the jobs, the MCP server, the updater and the Community sign-in front carry Microsoft's November
  security update of .NET (10.0.15)**, the runtime and ASP.NET Core.

## v3.1.2 — a fast device search, progress you can see, and steadier nights

### What's new
- **Searching a device in the detailed findings view is fast.** Searching for a device name, a CVE or an id in the
  findings list used to read every finding of the collection and could take more than 40 seconds on a large
  installation, sometimes ending in an error page. It now finds the device first and reads only its findings, so it
  answers in seconds. The page says what was searched, and "search anywhere in the text" is still there when you need
  it -- it answers without an error page.
- **Long steps show that they are moving.** A large report, the read of all findings after the reports, the long parts
  of the data sync and the building of the configuration items now report how far they are ("batch 161 of 266").
  You and support see that a long night is moving, not stuck.

### Fixes
- **A brief network failure no longer makes a night longer.** When a connection to the database failed for a moment,
  one part of preparing the views was given up and the rest of the night ran slower. SecurityInsight now tries such a
  connection again a few times before it gives up.
- **"Kept open" is no longer counted as "held".** Findings that were sent to your ticketing system before and are not
  in tonight's data are kept open there until enough complete runs confirm they are gone -- absence is not a fix. These
  rows were counted as "held", which read as rows held back. They are now counted and named on their own: "kept open
  -- not seen this run". What your ticketing system receives is unchanged.

## v3.1.1 — the clean-up of older collections gives way to your database earlier

### Fixes
- **The clean-up of older collections no longer holds your database at its limit.** It used to pause only when the
  database reached 85 % load, and each time it went on it pushed the load back up to near 100 %. Now it pauses at 70 %
  and goes on only once the load is below 50 %. Each clean-up also starts with one part at a time, and it adds more
  parts only while the database stays calm. Collections and your views keep their room, and the clean-up still
  finishes before the next run.

## v3.1.0 — SecurityInsight 3.1: a new platform, a support link you can see, and data you can trust

SecurityInsight 3.1 brings together the work since 3.0. Nothing changes in how you use it, and you do not need to do
anything: your installation updates itself.

### What is new since 3.0

- **A supported platform.** Since 3.0.85, SecurityInsight runs on .NET 10 and PowerShell 7.6, both long-term supported, on
  Microsoft's own images that are kept up to date with security fixes.
- **The Invardia support link.** The job that sends SecurityInsight's health and run results to Invardia support is
  now called "Invardia support link" everywhere you see it. It sends SecurityInsight's health and run results to
  Invardia support, so support can see problems and updates can roll out. One report that cannot be delivered never
  sends you a mail; the Jobs page turns amber only after three in a row.
- **Every error explained on invardia.com.** Each warning SecurityInsight shows has its own page there: what it means
  and who acts.
- **Data you can trust.** A run never waits in silence: the data sync says what it waits on, stops and repeats a part
  that is held up, and goes on. The data sync always goes first; old data is removed when it does not get in the way,
  and in time before the next run.
- **One list of the people who get which mail.** Configuration > Reports and alerts now shows one row per person and a
  tick per report and alert -- ticked means that person receives it, and nothing else decides. Get Started has a new
  step, "Who gets the reports": your current recipients are already filled in, so you check them once and confirm.
  Until you confirm, every mail goes where it goes today. Nobody is put on a list by default.
- **Findings past their due date** are counted at every installation, from the accepted time to fix of each asset type.
- Since 3.0 also: correlation decisions of your own, deleted users handled, reports that are never blank, a fresh start
  of the data that is quick, private installations that check their network first, inherited Azure tags, ServiceNow
  hand-off and management presentations -- each described in the 3.0.x notes below.

### Fixes

- A pipeline step that runs far past its usual time without progress opens a support case at once.
- A safety check in the CMDB step that held nothing back no longer raises a warning.
- A source is reported as behind only when its schedule says it should have been read.
## v3.0.88 — The removal of old data keeps up without getting in the way

### Fixes

- Old data is now removed almost continuously while nothing else runs, instead of in short bursts, and in several parts
  at once -- as many as the database can take, fewer the moment it is busy, so the web app stays responsive.
- It works towards the next scheduled run: when it would not be done in time it widens, and when it still cannot keep up
  it says so and support is told, so a backlog of old rows never grows unseen.
- The data sync still always goes first: while it (or a data out) runs, nothing is removed.
## v3.0.87 — A data sync step never waits in silence

### Fixes

- The data sync could wait for hours without a word when one part of its parallel work was held up in the database, and
  the run then never ended. It now says about once a minute what each part is waiting on and what holds it up. A part
  that makes no progress for 15 minutes is stopped and done again; if it is held up a second time, the step says so
  plainly and the run goes on instead of waiting.
- A pipeline step that runs far past its usual time without progress now opens a support case, so support acts on it
  the same day.
- The data sync comes first: while it (or a data out) runs, the removal of old data waits. The removal goes on, in small
  paced portions, whenever neither runs -- also during the rest of a run -- so even millions of old rows keep going down.
## v3.0.86 — Findings past their due date are counted at every install

### Fixes

- The executive overview's "Findings past their due date" said "not available yet" at nearly every install, because only
  a due date set in Defender for Cloud counted. A finding is now due at its first-seen date plus the accepted time to fix
  of its asset type -- the same rule as the Protection Score within the accepted lifecycle (30 days by default for a
  patch). A due date set in the source still wins, and the table says how the due dates were set.

## v3.0.85 — Moves to .NET 10 and PowerShell 7.6

### Security

- SecurityInsight now runs on .NET 10 and PowerShell 7.6, both long-term supported releases that keep receiving
  Microsoft's security updates.
- The web app and the AI assistant server run on the .NET 10 runtime on the same minimal Ubuntu 24.04 base as before.
- The job images move from Ubuntu 22.04 to Ubuntu 24.04 and carry PowerShell 7.6. They still install the latest Ubuntu
  security updates when they are built, and an image without PowerShell 7.6 is never built.
- The libraries the web app uses move to their current patched versions.

### Changes

- Nothing changes in how you use SecurityInsight: reports, mails, dates and numbers look as before.
## v3.0.84 — Security patch for the container images

### Security

- The web app and the AI assistant server now run on a minimal, patched Ubuntu 24.04 base. Number and time formatting in
  your own language and time zone work as before.
- All base images move to their latest patched versions, and the job images install the latest Ubuntu security
  updates when they are built.
- A .NET library the web app uses moves to its patched version.
## v3.0.83 — Old identities are removed completely

### Fixes

- When SecurityInsight moves to its standard identities, the old identity is removed.
- The update's check of the Invardia support app's access shows the access you agreed to.
## v3.0.82 — Older installs finish their alignment

### Fixes

- An update now removes the old single collection jobs that stayed behind after the collection was split in parts, once
  the new jobs have run and nothing starts the old ones any more.
- An older install now records which Invardia support app it trusts, so its support access is shown correctly. Nothing
  about the app's access changes.
- An install keeps its web app name and address. The update no longer reports the name as something to move.
## v3.0.81 — Large installs finish their runs and stay ready for the next one

### Fixes

- At the end of a run on a large install, the pages now catch up with the new run in steps that report their progress.
  Before, one long silent step at the end could be taken for a hang and stopped, so the pages kept older data and the next
  run and the waiting update could not start.
- An update that waits for a run is now installed right after the run ends, before the pages catch up and before any
  other run starts.
- A run that ended while its runner was stopped is now closed at once, so the next run is not held back.
## v3.0.80 — Deleted users, your correlation decisions, and reports that are never blank and complete

### Fixes

- A user Microsoft Entra ID lists as deleted is no longer shown as an active identity. It is retired at once and its
  findings close as "asset deleted in Entra ID", never as fixed. A user that is restored comes back by itself. If another
  source still sees the account, or its Active Directory account is still live, it stays active. Expect a one-time
  retirement of these identities at the first run after this update; the run log states how many.
- Your correlation decisions (never merge, always merge, keep this id) now apply to the assets themselves, not only to
  the correlation map. An install with no decisions is unaffected. When a decision splits an asset, findings that move
  with it never read as fixed.
- A report whose lookup could not be read now ends as not complete and keeps its last complete result. Previously it could
  finish as complete with some columns left empty.
- A large report that does not fit in one answer now keeps going while it is making progress, and says plainly whether the
  service was briefly unavailable or the report is too large.
- Users synchronised from Active Directory are no longer counted twice in the users count, so that number can fall at
  hybrid installs.
- During a move to the standard identity names, a run that failed for another reason, such as a platform timeout, is no
  longer reported as a problem with the new identity.

## v3.0.79 — A replaced device record no longer shows old vulnerabilities

### Fixes

- When a server is rebuilt or re-onboarded, Microsoft Defender can keep its older device record beside the new one. Its
  vulnerabilities no longer count for the asset once Defender reports the asset through a newer record: an update shown
  as missing only on the old record no longer appears on a server that has it installed.
- Findings that leave this way close as "report changed" with a plain explanation that the device record was replaced,
  never as fixed, so a connected ticketing system does not record a fix that was not confirmed.
- An asset whose only Defender record has stopped reporting keeps its findings, as before.

## v3.0.78 — A template change never holds an update

### Fixes

- When a release would change configuration templates you use, the code update now goes ahead; only the template change
  waits for an administrator to accept it, said in one plain line and shown on the Template releases page. Previously the
  whole update waited.
- If the database setup step fails during an update, the update is still held so new code never runs on an older
  database, but the failure is now reported and the next update run tries again by itself -- nobody has to act.
- Update behaviour is the same whatever the protection level of the installation's guards.

## v3.0.77 — Setup status shows the web app correctly; identity changes finish reliably

### Fixes

- The setup status no longer reports the web app as unfinished while its earlier address is back and the recent address is
  only forwarding visitors for its last few days: the web app is shown as running under its name.
- Moving an installation's managed identities to their standard names no longer stops by waiting for the temporary
  support access it opened itself.

## v3.0.76 — The web app keeps its address

### Fixes

- The web app keeps its name and its address at every installation, new and existing. An installation whose web app was
  recently given a new address gets its earlier address back: the web app is set up again under its earlier name in the
  same place, with the same settings and the same sign-in, and is checked before it is used.
- The recent address keeps working for a few days and sends every visitor to the earlier address; after that it is
  removed. Bookmarks to the earlier address work again straight away.
- Installations that never changed address are not touched.
- A support tool of the support access setup now reports its change correctly once it has been made.

## v3.0.75 — Support tools say what they do

### Fixes

- Support tools say each step as they go. If a tool cannot go ahead, nothing is changed and the tool says why.

## v3.0.74 — The install reports its support access as it is set

### Fixes

- Your install reports its support access as it is set.

## v3.0.73 — A setting for tenants with very many on-premises AD accounts that never sync to Entra ID

### New

- New setting *Exposure Graph: no asset for never-synced AD accounts that are not privileged* (Settings > Collection
  scope & limits, off by default). Some tenants have very many on-premises Active Directory
  accounts that never sync to Entra ID, and the Exposure Graph often lists them with only an account name. In those
  tenants they become hundreds of thousands of assets that nobody manages. Turn this setting on for such a tenant: a
  never-synced on-premises AD account then becomes an asset only while it is privileged (admin count, a critical or
  tier 0/1 AD group, an assigned role, a service account, a sensitive account or a Microsoft criticality level), whether
  it is enabled or not. Only on-premises AD accounts are affected; accounts synced to Entra ID, identities from other
  sources, groups, devices and findings are not. How many accounts were left out shows in each run's log and on the
  Data health page. Existing CIs of those accounts retire at once with the setting as the reason, and their findings
  close as asset retired, never as fixed. Turn it off and the next run records them again.

## v3.0.72 — A report the hunting service keeps timing out on is completed in smaller parts

### Fixes

- A part of a Risk Analysis report that the hunting service timed out on at every attempt used to be asked again at the
  same size, so the same report could stay incomplete run after run. Such a part is now asked again in smaller parts in
  the same run, nothing it held is lost, and the next run starts with smaller parts. A time-out that clears on a retry is
  handled as before.
- A report that has not been complete on several runs in a row is now said as such, with the date it started.

## v3.0.71 — Deleted secrets can be recovered, and faster urgent updates

### Security

- Deleted secrets and keys can be recovered during their retention period.
- The security pack lists the updater's rights.

### Updates

- When a fix must reach your installation quickly, it is now installed within minutes of being marked urgent instead of
  at the next daily update. A release that is not urgent still waits for your installation's own update time.
- The installation keeps the name it has on the vendor portal, and a failed read never clears it.

## v3.0.70 — Support requests arrive on your installation's own queue, and a private install checks its network first

### Security

- Support requests arrive on your installation's own queue, and the queue starts the support job; support access
  follows the rights you grant.

### Updates

- A private-network install now checks everything it needs before it creates anything: the private DNS zones, the
  subnets and their size, your rights on the network and the outbound path. Everything missing is listed at once with
  what to create, and nothing is created until it is there. A check that cannot be read is said and does not stop the
  install.

## v3.0.69 — Invardia support reaches your data during a support case you agree to

### Security

- Invardia support reaches your data during a support case you agree to, at the level you chose; access ends when the
  case closes.

## v3.0.68 — No false 'ran outside the pipeline' warning

### Fixes

- The daily check that every job ran as part of the pipeline no longer warns about the pipeline's own runs. It read
  the wrong part of the database answer, so every run's jobs were reported as having run outside the pipeline. A real
  job started outside the pipeline is still reported.

## v3.0.67 — One sign-in when the web app moves, and the identity move finishes

### Updates

- When the web app moves to its standard name, the old address now sends every page to the new one before anyone
  signs in, so a person signs in once, on the new address. Bookmarks keep working.
- The identity move now finishes: every container of the web app, including its sign-in front, uses the new identity
  after the switch and keeps using it on every later update.

## v3.0.66 — The update's sign-in check waits for Microsoft Entra

### Updates

- The update's check that SecurityInsight keeps its own sign-in set up reads its change back a few times over about
  half a minute, because Microsoft Entra can still answer the old value right after a write. The check no longer fails
  when the change has been made.

## v3.0.65 — Every SecurityInsight identity gets its standard name

### Updates

- Every update now reports, per role, whether the identity SecurityInsight runs as carries its standard name
  (`id-si-<role>`).
- Installations created before the standard names move to them, one role at a time: a new identity is made, given
  every right the old one holds, read back, put in use and proven; only then the old identity's rights are removed and
  it is deleted. The database access of the old identity is removed only after the new one holds all of it. The move
  is switched on per installation; until then the update only plans it.
- The SQL administrators group is renamed in place to its standard name (`grp-si-sql-admins`), with the same members;
  new installations create it under that name.

## v3.0.64 — Updates, support setup and runs no longer get in each other's way

### Updates and support

- A support setup step no longer starts the database setup job while an update is running; it says to start it
  after. Each update now reads only its own run of that job, so a parallel run can never hold an update. A database
  answer that picks the job as a deadlock victim is retried.
- Stopping a run and updating now checks again, right before the update starts, whether a run has started in the
  meantime, and warns when the next scheduled run is only minutes away. An update started by hand waits for a run that
  has just started instead of cutting it short.

### Pipeline

- When a run starts, a short network error while reading the settings is retried a few times before the run stops.

### Data

- `Reset-SIData.ps1` retries a temporary refusal (including a busy audit log) instead of stopping, and empties the
  tables in a few batches instead of one statement per table.

## v3.0.63 — The web app moves to its standard name, and keeps its sign-in set up

### Updates

- SecurityInsight keeps its own sign-in set up across updates; where the update may not do this itself, it says which
  support step is needed.
- Installations whose web app still carries the older name move to the standard name `ca-si-web`. The update creates
  the new app beside the old one, adds its sign-in address, and checks that it answers. Then the old app sends every
  page to the new address, so bookmarks keep working. The old app is removed only after the first person has signed in
  on the new one. An installation with a custom domain or a custom public address stops before that step and says so.
- The database setup job now records which Invardia Support app the installation trusts.

## v3.0.62 — The web app keeps its database access during an identity change

### Updates

- The web app keeps its database access during an identity change, also when it has more than one identity.

## v3.0.61 — Merge and split decisions on correlation suspects are saved again

### Web app

- Saving a merge or split decision on the correlation suspects page failed: the web app was not given the right to
  write those decisions to the database. The update now gives it that right, so decisions are saved and can be undone.

## v3.0.60 — The fresh start of the data empties every table the quick way

### Data

- `Reset-SIData.ps1`: a paused index build on a table (the index build pauses while a run is going) made the database
  refuse the quick empty, and the script then deleted the rows in small batches -- hours on a large table. It now stops
  that paused index build first; the index is built again later. Batches are used only where another table's key holds
  the table; any other refusal stops the script, and running it again goes on where it stopped.

## v3.0.59 — Every setting you never changed now has its default, also in the containers

### Settings

- A setting that was never stored now always takes its shipped default when a job starts in a container. Before, a few
  settings had no value at all in that case. This mattered for two identity settings that are on by default: the
  on-premises AD accounts that were never synced to Entra ID, are disabled and are not privileged, and the groups that
  Entra ID no longer has, are left out of the assets. Installations that never stored these two settings did not leave
  them out.
- **What you will see once:** at an installation that never stored these two settings, the first run after this update
  leaves those accounts and groups out, and retires their existing CIs with the setting named as the reason. This is the
  default your installation already had; it is now applied. To keep them, turn the setting off on the Settings page.
- The privilege tier classifier rebuilds its role catalog once after this update (one extra AI pass), because its saved
  settings now read the default explicitly.

### Data

- New support script `Reset-SIData.ps1`: a fresh start of the data at an installation that asks for one. It empties the
  data (assets, CIs, findings, history and their run records) in place and keeps the installation itself: settings,
  templates, the audit trail, users, roles and grants. It shows a plan first, refuses while a run or an update is going,
  and reads back the result. The identity ids are kept unless asked for.

### Data out

- The progress line of an output now says "rows to read" when it estimates from the data, and "planned" only when it
  estimates from the last batch. Before, a first estimate from the data read as the number of rows to be sent.

### Updates

- When the web app's sign-in still requires an assignment and the update may not change that, the update now names the
  published script to run, with both ids filled in.

## v3.0.58 — The data sync no longer slows to a crawl at large installs

### Data sync

- The step that tracks each finding's lifecycle works through the findings in key ranges. At a large install every range
  read the full list of retired assets, whatever its size, so each range cost about 8 seconds. The range size then shrank
  to a single key and stayed there, and this one step could take a day or more. Each range now reads only the assets it
  needs, and the range size takes a fixed cost per range into account, so it grows back to thousands of keys per range.

## v3.0.57 — A stuck job no longer holds back the daily run

### Pipeline

- SecurityInsight now notices when one of its own jobs is still listed as running but shows no sign of life: an update,
  a pipeline run or a clean-up of old data. Such a job is stopped, and the waiting run starts. A job counts as stuck
  15 minutes after it last reported that it was working, or 30 minutes after it started if it never reported. A job
  that is still working is never stopped. Before, a stuck update or run could hold back the daily collection for many
  hours or even days.
- When building the CI list, a temporary answer from the database while saving asset ids is now retried on a new
  connection. Before, one such answer could end a long build and the work had to start again.

### Support

- The update again makes sure the queue that carries support requests exists. For the last few days it warned on
  every run that the queue could not be checked.

## v3.0.56 — One moved asset no longer holds back every vulnerability close

### Vulnerabilities

- When an asset's identifier moves to another CI and the correlation keeps both CIs, a finding stored under the old CI
  could not be matched with certainty. Before, a single such finding stopped every close in the whole run. Now only the
  CIs concerned are held for that run, and nothing on them is opened, updated or closed. Every other finding opens and
  closes as normal. The run's warning names the CIs and the findings.

### Setup and updates

- The database setup step can run its grants alone: users, memberships and grants, with no procedure, schema or setting
  changed. It may therefore run while a pipeline run is in progress.
- Moving an install to its new identity names now counts a schema the new identity owns as already carrying the old
  identity's rights on it, so the move's read-back is complete.

## v3.0.55 — The database setup step finishes in one run

### Setup and updates

- On an install with the optional Support app, the database setup step now prepares the support tables in the identity
  database before it gives the engine and the update their roles there. The first run of the step therefore succeeds
  and reads everything back, where it used to need a second run.

## v3.0.54 — An update waiting at the end of a long run is no longer missed

### Pipeline

- A run keeps its hold on the install for the whole run, including the long work at the end. An update that is waiting
  is therefore always started right after the run ends, and never left for the next night.
- The database statistics are refreshed once, after the run's results are published, so the pages are fast as soon as
  the new results show.

### Setup and updates

- The update finds the Support app by itself when it keeps the database setup step's permissions in place.
- The index build step, the database setup step and the update connect through the same retrying connections as the
  rest of the product. A short network or sign-in hiccup no longer stops them.

## v3.0.53 — The database setup step keeps itself working, and a missing Defender licence is said plainly

### Setup and updates

- The database setup step keeps its database rights after every update: its membership of the SQL server's admin group
  is checked and read back before the step runs, and the update renews a time-limited membership before it ends; a renewal that fails while the membership is still valid is
  a warning, never a stopped update. A step started right after a new membership waits for it to take effect.
- Moving the SQL server's admin from one group to another is proven by a sign-in through the new group, and rolled back
  automatically when that does not succeed.
- Every update turns on background statistics in each product database, so a page never waits for the database to
  refresh one.
- The support step uses your own Support app. The setup step's lines now reach the install's log
  workspace.

### Risk analysis

- A report whose Defender table is not in the tenant (for example without Defender vulnerability management) is shown
  as not applicable again, even when Defender does not name the missing table. A real query problem still fails the
  report on its first try.

## v3.0.52 — Pages stay fast after every run

### Pipeline

- At the end of every run the pipeline brings the database's statistics up to date for the tables the run rewrote, before
  the pages move to the new run and again after their copies are refreshed. Pages are planned on current figures and never
  wait for the database to update a statistic while you look. It changes no data; if it cannot run, the run still completes
  and the log says so in one line.
- New installs set the database to update a stale statistic in the background, so a page read never waits for it.

### Web app

- A device's close-loop list reads only that device's findings, whatever the database's statistics say (it could read the
  whole findings table for one device and take more than a minute).

## v3.0.51 — Fast views, and an update never makes the web app hang

### Web app

- Every view reads narrow indexes and stored columns instead of each row's full source record. The navigation, the data
  check every page makes, the device page, a CI's findings and daily history, the Summary view, the correlation figures,
  the audit trail, the guard events and the change history answer in a fraction of the time they took, also while a
  pipeline run is going. Every rewritten view was checked to show exactly the same rows as before.
- A built-in check now refuses any new or changed view that would read the full source records or scan a large table, and
  the web app writes one log line for any page read that takes two seconds or more.
- While an update changes the database, the web app answers at once with a short "SecurityInsight is being updated"
  notice and comes back by itself, instead of hanging. Its health probes no longer touch the database.
- The device page names each finding from the published run.

### Pipeline

- The findings per CI are compared by their content in one read per record: a step that read far too much at a large
  install is many times faster, with the same results.
- The run's time is no longer stored inside each finding's record, so a finding that did not change is not rewritten on
  every run. What SecurityInsight sends to SQL and ServiceNow is unchanged, byte for byte.
- The large source records are kept outside the table rows, so every other read of those tables reads far less.

### Updates and telemetry

- An update no longer re-creates unchanged database procedures and triggers, so tables read at sign-in are not locked
  while it runs.
- A run record that could not be sent to Invardia is kept for up to seven days and sent later, in paced rounds.
## v3.0.50 — The private build pool is never removed

### Updates

- On a private install, an update no longer removes the image build pool to change its size class. A pool of another
  size class keeps it and only goes back to no agents between builds (read back). Removing and re-creating it could leave
  the install without a pool, so that no update could build its images.
- A build pool made by setup or an update starts with one agent (Azure does not create a pool with none), and is then
  scaled to no agents between builds and read back.
## v3.0.49 — One stable CI per machine, every CI state told to ServiceNow, and users' sign-in methods in full

### Configuration items

- A CI's id is stable: an id that was merged into another CI is never used again. A record that still points at it now
  builds the CI it was merged into, and a CI that came back after a merge is retired once, as merged into the right CI,
  with its findings moved there. Nothing is deleted.
- Every CI that is not active is sent to ServiceNow with its state and a plain reason (for example "merged into <id>
  (<name>) -- the same machine; use that CI", or "not seen since <date>"), and the CI that replaces a merged one names it.
  A CI is never dropped from what SecurityInsight sends. CIs that were sent as retired without a reason are sent once
  more, with it.
- Exposure Graph keeps listing machines long after they are gone; a device or Azure resource that only Exposure Graph
  still lists now goes "not seen" and is retired after its grace period, and Exposure Graph no longer keeps a CI active
  when the source it mirrors stopped seeing it. Accounts are not affected: a dormant account stays, as a risk to report.
- The SQL Server resource of an Azure VM is a linked child of the VM's CI, never offered as the same machine.
- A Defender device without a name gets a generated name, so no CI is nameless.
- On the first build after this update every CI is rebuilt once.

### Identity collection

- Every user's sign-in methods in full -- each method with its details and the device a Windows Hello or Authenticator
  key lives on (linked to that device's CI) -- read in the background by its own job, privileged users first, then users
  whose methods changed. Collections never wait for it. A setting chooses who is read (every user, privileged only, or
  none); the first full read of a large tenant takes many hours, later runs read only changed users.

### Private installs

- An install with a private registry scales its image build pool up only while it builds, and back to none after, so it
  costs nothing between updates. The heartbeat reports the pool's size.
- Building indexes on large tables is its own job, and pauses the moment an update waits -- the update never waits for it.

### Web app

- The Assumptions page shows every collection-scope setting with the value in force.
- An asset's close-loop table names each finding (title and kind: CVE, recommendation or certificate) and counts every
  item.

## v3.0.48 — Updates never stop a running pipeline, and a faster identity read at large tenants

### Updates

- An update never cancels a running pipeline any more. It waits for the run to end and is installed between two runs; a
  waiting update still goes first. Before, an update that had waited 6 hours cancelled a run that
  started on an older version, also after its Risk Analysis had finished.
- An update now waits up to 90 minutes for its image build. An install with a private registry builds inside its own
  network, which can take longer than the 30 minutes allowed before.

### Identity collection

- With "skip on-premises accounts that were never synced, are disabled and are not privileged" on, those accounts are now
  left out in the Exposure Graph query itself instead of being read and then dropped. At a large tenant this reads far
  fewer nodes. Any account with a sign of an Entra ID or of privilege is still read and decided as before; the log says
  how many were not fetched.

## v3.0.47 — A new install's first collection runs Risk Analysis without waiting

### Pipeline

- On a new install's first collection, the merged assets are shown as soon as the asset build has finished. The run
  waited for that step before it went on, so at a large tenant Risk Analysis and every later step stood still for
  hours. It now runs beside the rest of the run: Risk Analysis starts at once, nothing that needs the data sync starts
  before it has ended, and the data sync runs again at its own place as before.

### Invardia support

- The support status shows which databases have support access set up.

## v3.0.46 — Every download verified, and short support sessions

### Install

- The Community installer checks every download before it installs it.

### Invardia support

- A support session lasts at most 8 hours.

### Database setup

- The database setup job now finds the identity each part of SecurityInsight signs in as, also while an install is
  moving to new identity names.

### Wording

- Comments in the shipped scripts use plain wording; a test keeps it that way.

## v3.0.45 — Nobody needs database admin rights any more, and the support level applies to every SecurityInsight database

### Database setup without a person

- **SecurityInsight has its own database setup job that creates and checks every database user and right the product
  needs** — for the engine, the updater, the web app, the MCP server and asset tagging. A new install starts it and
  waits for its result. Every update keeps it in place and runs it before installing new code; if it fails, the update
  waits and your installed version keeps running. For an existing installation, add the database setup job's identity
  to your SQL admin group once; after that every update runs it. The scripts that did this by hand remain available as
  a fallback.
- Asset tagging's database access is now given by the update itself.
- Two manual database scripts are no longer needed for the Pro database: every update applies those tables.

### Invardia support

- The support level you set in the Invardia portal applies to every SecurityInsight database.
- The request queue Invardia support uses to open a session is now created by the update at every install.

### Web sign-in

- The web app runs behind sign-in front 1.4.5 (wording in its code only; no change in behaviour).

## v3.0.44 — Two identity scope settings on by default, and the same install lines everywhere

### Changed defaults

- **Exposure Graph identities without an asset are now left out by default.** Two
  settings in Settings > Collection scope & limits are now on:
  - *No asset for never-synced, disabled AD accounts*: an on-premises AD account that was never synced to Entra ID
    becomes an asset only while it is enabled or privileged (an admin count, a critical or tier 0/1 AD group, an
    assigned role, a service account, a sensitive account or a Microsoft criticality level).
  - *No asset for groups Entra ID no longer has*: a group with an Entra object id becomes an asset only while Entra ID
    still has it (active or in its deleted items). Nothing is decided when the group list could not be read completely.

  An install that never chose a value takes the new default on its next run (applied from 3.0.59); a value you chose
  is kept. What is left
  out is counted on the Data health page ("Left out by your choice"); the existing assets of such accounts and groups
  retire with a reason naming the setting, and their findings close as asset retired, never as fixed. Accounts synced
  to Entra ID, devices and findings are not affected. Turn a setting off and the next run records them again.

### Install

- The two install lines are now the same in the README, the release notes, the release page, the documentation and
  the installer's own help: Community downloads from the latest public release, Pro and the trial from invardia.com,
  and line 2 is the same for both.

## v3.0.43 — Reports that no longer go missing on large tenants, bigger jobs for the heavy steps, and the support level set in the Invardia portal

This release carries everything of 3.0.42 (which was not released to every installation) and two more fixes.

### Report fixes

- On a large tenant, a few Risk Analysis reports (attack paths and administrator sign-ins to devices) could end
  incomplete because Log Analytics was briefly short of memory while it built the lookup of each asset's CI. SecurityInsight
  now waits and asks again in that case, and builds such a lookup in parts where each part reads only its share of the
  CIs. The rows are the same; the reports complete.
- The device vulnerability reports (missing CVEs, recommendations, end-of-support software) now return their rows on a
  tenant whose Defender has the vulnerability data but no device inventory table (for example Microsoft Defender for
  Business). Before, one optional lookup of the device name failed the whole report. On a tenant with the device
  inventory the rows are the same as before, and every open finding keeps its history.

### Stability fixes

- The heavy jobs (the collections, correlation, Risk Analysis, the data sync and vulnerabilities) now run with at least
  4 CPU / 8 GiB. Every update raises an existing install's heavy jobs to that size; a job is never made smaller.
- A collection whose run was stopped by an update, by support or by a person is now reported as partial, with that reason,
  instead of failed. Only a run that itself failed reports a failed collection.
- Stopping a run and updating is one checked step, with a read-back after each part.
- The one-time cut-off now reads its own setting back correctly.

### Support access

- The level of access the Invardia Support app has (none, troubleshoot or setup) now follows the level you set in the
  Invardia customer portal. The updater reads it from Invardia on every run and applies it; a level you lower or remove in
  the portal is applied the same way.

## v3.0.42 — Device reports on Defender for Business, a stopped run is no longer "failed", and the support level set in the Invardia portal

### Report fixes

- The device vulnerability reports (missing CVEs, recommendations, end-of-support software) now return their rows on a
  tenant whose Defender has the vulnerability data but no device inventory table (for example Microsoft Defender for
  Business). Before, one optional lookup of the device name failed the whole report and it showed no rows. On a tenant that
  has the device inventory, the rows are the same as before, and every open finding keeps its history.

### Pipeline fixes

- A collection whose run was stopped by an update, by support or by a person is now reported as partial, with that reason,
  instead of failed. Only a run that itself failed reports a failed collection. The last complete collection shown stays the
  one you can see.
- Stopping a run and updating is one checked step, with a read-back after each part.
- The one-time cut-off now reads its own setting back correctly.

### Support access

- The level of access the Invardia Support app has (none, troubleshoot or setup) now follows the level you set in the
  Invardia customer portal. The updater reads it from Invardia on every run and applies it; a level you lower or remove in
  the portal is applied the same way.

## v3.0.41 — A one-time fresh start for large installs, and a private AI account on a private install

### Correlation

- On your request, a one-time cut-off can be set: from the next collection of each source on, the
  records collected before the cut-off are no longer taken into the CIs, and a CI that only those older records built is
  retired, with the cut-off named as the reason. Nothing is deleted. It is meant for a fresh start of a large install whose
  older collections hold records that are no longer wanted. The script shows how many CIs would retire before anything is
  set, and records who set it and why.

### Install fixes

- On a private installation, the optional AI account is private, or AI stays off and setup says why.

## v3.0.40 — Inherited Azure tags in every collection mode, and safer installs

### Azure fixes

- Azure records collected in parts (a producer with workers, the mode of larger installs) now carry the tags they inherit
  from their resource group, subscription and management groups, as single-job collections already did. The tags are
  read once per collection, tenant-wide, and the log says how many of each were read.

### Install fixes

- The install creates the web app's Key Vault key for its sign-in keys and gives the web app its right to use it, then
  reads both back, so a new install no longer waits for its updater (which may not give that right). Where the person
  installing may not assign roles, the grant is listed as a task and the install goes on.

## v3.0.39 — Collection runs only inside the pipeline

### Pipeline fixes

- The Endpoint, Identity and Azure collections each ran a second time a day on a timer of their own, outside the
  pipeline. That extra collection belonged to no run. Now a collection that is a step of the pipeline is started only by
  the pipeline: the update takes the extra timer away (and reads it back), and a timed start is skipped with one line in
  the log. Installs that run their jobs on their own schedules keep their timers.
- The Jobs page shows these three collections as their pipeline steps again; saving the pipeline keeps them.
- The verification job now checks that every collection ran inside the pipeline or was started by a person, and warns
  about any that did not.

## v3.0.38 — A private install's replies find their way back, and two editions never share a resource group

### Install fixes

- A private install connected to your hub network can now be given the address ranges your people browse from and
  your hub firewall's private IP. On a network SecurityInsight creates, it then adds the route that sends replies back
  through your firewall (and reads it back). Without that route the web app times out from your own network even when
  DNS and the peering are right. On your own network nothing is changed: the network hand-off names the route your
  network team adds. The two questions are asked only when a hub network is given.
- When the resource group already holds the other SecurityInsight edition, the install stops before it creates anything
  and asks you to choose another resource group name.

## v3.0.37 — New installs get short, standard names

### Install fixes

- A new install names its resources the short, standard way: the resource group rg-si, the workspace log-si, the
  collection endpoint dce-si, the Container Apps environment cae-si and its network vnet-si (in the install's own
  resource group). The resources whose names must be unique across Azure end in six characters derived from the install:
  sql-si-, kv-si-, stsi and acrsi followed by those characters. They stay the same on every resume and re-run.
- Names you choose still win. An existing install, a resume of one and every update keep the names they already have;
  nothing is renamed.

## v3.0.36 — A private install finishes cleanly

### Install fixes

- On a private install, the final health check reaches the database through its private endpoint.
- Adding a member to a group SecurityInsight has just created now waits for Microsoft Entra to know the group (up to five
  minutes, said in the log) and reads the membership back, instead of stopping with "does not exist".
- The support-access step ends ok on a fresh install: its consent part is skipped in a database that does not yet carry
  the support tables, and the next step adds them.

## v3.0.35 — Inherited Azure tags are stored, and a permission the installer cannot read no longer stops it

### Azure fixes

- Every Azure record now carries the tags it inherits from its resource group, its subscription and its management
  groups, each with the level and the name of the container it comes from (the nearest one wins when a tag is set at
  several levels). Before, these were read only when a classification rule used them, and management-group tags were
  not read at all. They are read tenant-wide, one read per level, and a level that cannot be read is said by name.

### Install fixes

- When the installer may not read or assign a permission outside SecurityInsight's own resource group (for example at
  the tenant root), that grant is listed as a task for someone with the rights, and the install continues with a
  warning. Only a failure inside SecurityInsight's own resource group stops it.

## v3.0.34 — A new public install gets past its Key Vault

### Install

- A new public install no longer stops at the workspace step with a Key Vault error. Private installs are unchanged.

## v3.0.33 — A private install's build machines get their outbound path

### Install

- On a private install, the subnet that SecurityInsight creates for its private endpoints is given outbound access,
  read back, so the container registry's build machines can start (new Azure subnets have no outbound access by
  default). This is outbound only: nothing becomes reachable from outside.
- Before the build agent pool is made, its subnet is checked for an outbound path. On a network you provide that has
  none, the install stops with the one step your network team takes, instead of making a build pool that cannot start.
- An update repairs a private install whose build pool does not run.

## v3.0.32 — A private install waits for its build agent pool

### Install

- On a private install, the container registry step waits for its build agent pool while Azure creates it in your
  network (up to 30 minutes, with a progress line every minute), instead of stopping and asking for the install to be
  run again. A pool that Azure left failed is made again on the next run.

## v3.0.31 — A private install builds inside your network

### Install

- A private installation builds and keeps its updates inside your network; the private endpoint and DNS zone it needs
  are checked from the install machine and listed for your network team.
- A private install uses an internal Container Apps environment; one already in use is never removed automatically.
- Resuming an install downloads the release again when the one downloaded before is another edition or version.
- The install shows the released version it installs, with no old product names, release-candidate labels or cost
  figures in its output.

## v3.0.30 — Old rows are removed during runs, duplicates are merged, and Pro installs open straight from Invardia

### Install

- A SecurityInsight Pro install without its licence yet waits for the licence at the licence step, instead of stopping
  with an error. The licence then arrives through the updater.

### Data and runs

- Old finding rows that are no longer needed are now removed while a run is going, paced by the database's load. Before,
  this clean-up only ran between runs, so at installs whose runs follow each other it never ran and the database grew.
- An asset record that SecurityInsight first stored under a temporary key, and then again under its lasting key, is now
  merged at once: the copy is retired as merged, also in the ServiceNow hand-off. A new install's first run waits until
  the lasting keys are ready, so it does not create such copies.
- A database connection that the driver recovered mid-statement, or a database briefly unavailable, no longer fails a
  run step: the statement is sent again where that is safe.
- A full database now has its own report cause and step, and a failed step names its error instead of "unknown".
- The web app's key check says "not known" when it cannot read the key's permissions, instead of reporting a problem
  that is not there.

### Status reports

- Each install reports its web app's address in the form Invardia reads, so the "Open SecurityInsight" link appears in
  Invardia's overview and in every support mail about the install.
- Each install reports the state of its one-time setup steps, each from a check that ran at the install. A step that
  could not be checked is not reported.

### Releases

- Every release hands Invardia its install parameters, the API and MCP reference (generated from the code), the docs
  pack and its release notes, so the portal and invardia.com show them for the version you run.
- Each script's documentation names its file, so every published script shows its documentation page.

## v3.0.29 — A clean package, a complete hand-over, the Key Vault always in the right shape

### Install

- The Key Vault is set up with its network settings from the start, and they are read back. That holds whether the
  install creates it, takes back one deleted earlier (with its keys and secrets) or finds it already there. On a
  private install this keeps Azure's trusted services able to manage the vault's
  keys.
- Re-installing over a deleted SecurityInsight Key Vault now takes it back, instead of stopping on the deleted vault.
- The region check tests with the same settings the real resources get, so a policy in your subscription that requires
  those settings no longer refuses the check.

### Releases

- The support scripts come as one complete set: a checksum for every file, and the documentation with the same
  version.

## v3.0.28 — The install checks the region first

### Install

- Before anything is created, the install asks Azure whether your region takes new resources in this subscription. If
  it does not, it stops at once and names nearby regions that do. A policy that refuses the check is reported, never a
  stop.
- A private install reads each private endpoint's address from its network interface, the one place Azure always
  fills in.

## v3.0.27 — Install in two lines, everywhere

### Install

- The Community edition installs in two lines: line 1 downloads the installer from the latest GitHub release, line 2
  runs it with your tenant and subscription. No git clone and no config file.
- The README, the script help and the docs show the same two lines, with only the parameters an install uses.

## v3.0.26 — Pro installs from Invardia, and the install fixes of 3.0.22-3.0.25

### Install

- The Pro install line from invardia.com now gets the Pro package from Invardia (signed and checked); you sign in
  once. The Community line keeps GitHub.
- Includes the install fixes of 3.0.22-3.0.25: a Pro install without a licence starts, a new subscription's quota is
  not a stop, a second run in one window signs in again, and the person installing gets their data roles.

## v3.0.25 — The install gives the person installing their data access

### Install

- The install grants the person who installs (a user, not an app) the data roles on the new workspace, storage and Key
  Vault -- Azure refused them before because they were asked for as an app.

## v3.0.24 — Running the install again in the same window signs you in

### Install

- A second run of the install in the same PowerShell window signs you in again instead of stopping with "You are not
  signed in".

## v3.0.23 — The install goes on in a new subscription

### Install

- In a subscription where Container Apps was never used, the install no longer stops at the quota check (Azure shows
  "0 of 0" until the install registers Container Apps): the quota is checked when the environment is created.
- Running the install again in the same PowerShell window signs you in again instead of stopping at the subscription check.

## v3.0.22 — The Pro install without a licence starts

### Install

- The Pro install from invardia.com (no licence yet) no longer stops at "Check the tenant and subscription": it deploys the
  whole environment and waits for the licence, as intended.

## v3.0.21 — One install command, every setting a parameter

### Install

- SecurityInsight installs with ONE command line: every setting of the guided install is a parameter (what you leave out
  keeps its default), so the install runs unattended and reports each step as it goes. Only the tenant and the
  subscription are required.
- An install needs no licence: it deploys the whole environment -- engine jobs, database, web app and updater -- and runs
  nothing paid until the licence is assigned to the installation; then it takes its licence and install key by itself.
- A stopped install continues with the same command and -Resume.

## v3.0.20 — Tags your Azure resources inherit, tags in ServiceNow, and an easier CI page

### Tags

- An Azure resource now also carries the tags of its resource group and subscription that it does not set itself, each
  marked with where it came from. The resource's own tag wins over a parent's, and the resource group's over the
  subscription's. Many resources have no tags of their own, so this fills in owner, application and purpose for them.
- Every tag of a CI -- its own first, then the inherited ones -- is also available as one field, for rules, reports and
  connectors.
- The ServiceNow CI hand-off offers three new columns at the end: all tags, own tags and inherited tags, each sent as
  "name = value; ..." text (an inherited tag with "(resource group)" or "(subscription)"). Your ServiceNow team adds the
  columns (long text) to the import table and the transform map; until then ServiceNow ignores them.
- Every CI is rebuilt once on the first build after this update, so the new tag fields reach all of them.

### The CI page

- Tags show their values ("name = value"), not only their names.
- Field names stay on one line, every small table's columns can be made wider or narrower (drag the edge, or the arrow
  keys; double-click resets), and the field sources table shows each field's value.

## v3.0.19 — Old collections are cleaned up while runs go, and every update sizes the jobs again

### Database housekeeping

- At an install whose runs go back to back, the rows of older collections are now removed while a run is going too,
  instead of only when nothing runs. The removal waits while the database is busy and gives way at once to a ServiceNow
  send, so a run and the send are never slowed by it. The newest two complete collections and the published one are
  never touched.

### Updates

- Every update checks the CPU and memory of the jobs and the web app again, and raises one that is too small for your
  tenant. Until now only a new install did this.

## v3.0.18 — Cleaner assets: one CI per machine, a choice of what goes to ServiceNow

### Assets and correlation

- A domain-joined computer's Active Directory account is no longer a second device CI beside the machine itself: it is
  linked to the device it belongs to.
- A data-quality check finds devices that are probably the same machine (the same name, or a shared hardware id) but
  were kept apart. They are listed for a person to decide "same machine" or "not the same"; the decision is kept and used
  by the next build.
- An organisation can choose to leave out Active Directory accounts that were never synced and are disabled, and groups
  that no longer exist in Entra. Both choices are off by default; privileged accounts are always kept.
- A device whose source reports a placeholder name (such as "dummydevicename") takes its name from another source, or a
  clear generated name ("unnamed-device-" and a short id); a placeholder name never joins two devices. Every CI is
  rebuilt once with this release so existing CIs take their new names.
- An asset proven deleted (in Entra ID's deleted items, a delete in Azure's resource changes, or a removed Intune device)
  can be retired at once instead of after 30 days, with its open findings closed as "asset deleted". Only a proven
  deletion counts; an asset that is merely missing keeps the usual waiting time. One switch per source, all off by
  default; a restored object comes back with its findings.

### ServiceNow and the other outputs

- The ServiceNow configuration items can be limited by asset type and operating system in the connector's scope, so,
  for example, mobile phones stay out while Windows, Linux, IoT, network devices, printers, macOS and Azure resources
  go.
- The ServiceNow check counts the configuration items it would send without a database error.

### The web app

- The CI list's lifecycle filter (active, not seen, retired) is in both filter panels.
- Small fixes: page texts name menu paths the same way everywhere.

### Community edition

- The Community release carries the source of the web app's sign-in front, so a Community installation builds it
  from the release itself.

### Updates

- The updater keeps its timers and its installation id in step with the installation, and reports the hand-off's
  progress in its status.

## v3.0.17 — A faster, visible hand-off to ServiceNow

### ServiceNow and the other outputs

- The vulnerable items are built about three times faster: each finding is decided before it is shaped into a row,
  and only the findings that get a row are shaped.
- The pass over closed findings reads only the ones that were sent before, when the scope leaves the others out --
  on a large installation hours less, with the same rows sent.
- Progress while it sends: the phase, the rows sent of the rows planned, the rows held and the time left, in the log and
  in the database once a minute. A send without progress for 10 minutes says so; it never stops the send.
- A send that ServiceNow refuses, or that is held, says so at once and stops; nothing is counted as sent that was not.

### Invardia

- The installation names itself to Invardia by its lasting installation id on its status reports, the update check and
  the licence request, and shows its hand-off progress in its status.

## v3.0.16 — Vulnerable items reach your own ServiceNow staging tables

- Vulnerable items now reach your own ServiceNow staging tables, whatever their name. SecurityInsight still sends only to
  staging tables, never straight into ServiceNow's own record tables.
- A value longer than its ServiceNow column now holds only its own row: the other rows are sent, and the held rows go
  once the column is wider. The run names the column, the longest value and up to five held records. Before, one such value
  held the whole hand-off.
- A vulnerable item's identifier longer than 100 characters (a long attack path) is shortened the way the ServiceNow
  staging specification describes -- its first 59 characters, '~' and a hash -- so it fits the 100-character column.

## v3.0.15 — ServiceNow sends without waiting for the data sync

### ServiceNow and the other outputs

- The data out (ServiceNow and the other outputs) runs as its own job. It starts as soon as the newest collection's
  findings are stored, so the push no longer waits for the rest of the data sync. A resend is a start of that job: it
  takes minutes, not a full data sync. An installation without the new job keeps sending from the data sync as before.
- A data sync started on its own no longer clears old collections before it sends.

### Housekeeping

- Old collections are removed in the background only while no run, data sync or data out is going, a little at a
  time. Progress is shown in the status. The newest two complete collections are always kept.

### Mail

- The technical owners' monthly review mail is sent again. In 3.0.13 and 3.0.14 it stopped while its subject was built.

## v3.0.14 — the ServiceNow push sends its rows

- The CI hand-off and the vulnerable items reach ServiceNow: in 3.0.11 to 3.0.13 the push stopped before it wrote a row,
  because part of it could not be found when the data sync ran it. The next push sends everything that is due.

## v3.0.13 — security strengthened

- **Security strengthened.** The web app and the AI assistant carry the security improvements of this release.

## v3.0.12 — security hardening

- **Security strengthened.** Everyone signs in once more after the update.
- Error messages on pages say what you can do.
- AI summaries use your Azure OpenAI service, directly or through an Azure API Management gateway in front of it.

## v3.0.11 — the ServiceNow push no longer stops with a database error, a faster Detailed risk analysis

### ServiceNow

- The CI hand-off and the vulnerable items no longer stop with a database error, as both did in 3.0.10; the next push
  closes the batches that stayed open as failed and prepares their rows again.

### Risk Analysis

- The Detailed risk analysis reads its results once after the reports instead of twice: the key figures are counted in the
  same pass as the AI summary, with the same numbers as before. On the largest installs this saves hours of the step.

## v3.0.10 — the data sync's counts, the ServiceNow hand-off, management presentations

### The data sync

- The finding lifecycle's counts reach the run again: what was new, seen again, reopened and closed is in the log, the
  run record and the mail, and the one-time clean-up of stale open findings runs. Before, a data sync on 3.0.9 said that
  nothing was closed after its closes were written.

### ServiceNow

- The CI hand-off to ServiceNow is prepared from every run.
- The check before each send no longer needs ServiceNow's table list; without it only the column check is left out,
  with a warning.
- A refusal says what ServiceNow said. A role ServiceNow names is said as its word; when it names none, the message says
  which access SecurityInsight usually needs there, never as if ServiceNow had said it.
- "For your ServiceNow team" lists the complete set: the user SecurityInsight signs in with, every role it needs, the
  access settings of each staging table, and every call SecurityInsight makes to the instance.

### Runs

- A pipeline step whose container stops before SecurityInsight starts in it is started again once. Only the step's own
  run log counts as proof that it ran, not another job's log in the same minute.
- The column fill check says what it measured: a value on a smaller share of the report's rows. Rows that had the value
  and left the report are no longer reported as blank columns.

### Management presentations

- A wizard builds a PowerPoint presentation from the Executive report, and the monthly management pack is attached to
  the management summary mail.
## v3.0.9 — stability for large installs, the Risk Score in columns, a one-line install

### Updates reach every install

- A waiting update now goes first: while an update waits, the pipeline starts no new run and the scheduled collections
  hold, so the update installs when the current run ends. After six hours of waiting, the update ends a run that started
  on an older version itself, installs, and the next run starts on the new version. A run of the new version is never
  ended.
- A pipeline step whose job ended on its own (for example after a broken database connection) is now closed by the
  pipeline, so the run goes on by its normal rules instead of holding the install.
- Cancelling a run now works while the run is still active.

### The data sync on large installs

- Storing the findings per CI, the finding lifecycle, the CI totals and columns, and the day's totals per department and
  service now work in bounded key ranges, each with its own commit. No single database command grows with the size of
  the collection any more; each range is measured and written to the log. A data sync that stops part-way is finished by
  the next one, with the same result.
- A brief Azure SQL failure (a failover, a busy log, a broken connection) is retried on a new connection for up to about
  nine minutes before the step reports it. Query errors still fail at once.
- While the findings per CI are being replaced, the published pages keep showing the previous complete set.

### Status and reports

- The run reports of the collection jobs (identities, Azure, devices, public IPs, privilege tiers) reach Invardia again,
  and every run report lists the steps that succeeded, so a resolved problem closes by itself.
- The status report names a step that runs far past its usual time with no sign of progress.
- The asset pages' copy no longer raises "data behind" while it is being refreshed after a publish.

### Findings and the web app

- The parts of the Risk Score are columns in the Detailed and Summary findings, shown by default: the base and the points
  of each side, the factors with their points, and the weight. They can be sorted and filtered. Earlier collections are
  filled by the data sync, newest first.
- The findings grids use the same filter panel as the CI list: labelled filters, what you are looking at, sort and order.
- Shift+click selects every row between two rows; Ctrl+click selects one more.
- Operations > Jobs shows a job run started outside the pipeline, and what a running step is doing now, with its progress
  where the step counts it.
- Get Started, the mail step: the steps are in the right order and say what is needed.

### Install

- The install takes the common answers as parameters. The quickest install is one line:
  `./setup/Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>'`. The install page and the
  README show five samples.

### Checks and mails

- The check "far fewer assets from one source" no longer sends a mail; it shows on Operations only.
- A ServiceNow import that does not accept some CIs is raised on the Guards page again, and clears when a complete batch
  is accepted.

## v3.0.8 — the status report after 3.0.5

### Status report

- Since 3.0.5, an install stopped sending its status report to Invardia: the step that reads a job
  start's own values left part of its setup behind for the job that ran next. That step now cleans up after itself,
  and the status report and run reports go out as before. Nothing else changes.

## v3.0.6 — findings filters as dropdowns

### Findings

- **Category, Subcategory and Department are dropdown filters** on the findings of both the Summary and the Detailed
  results, like Domain and Report: tick one or more values, with the number of findings for each. A collection loaded
  before this update shows them as dropdowns after its next data sync.
- The value menus of every filter are easier to read: each value sits next to its tick box.

## v3.0.5 — job starts without a template

### Azure Container Apps

- Azure Container Apps changes what starting a job with its own container settings requires. SecurityInsight no
  longer sends container settings when it starts a job: every start from the web app (Run now on a pipeline, a stage
  or a step, a template release, the mail-only run after a request, the ServiceNow check) is a plain start. The values
  that start needs, such as what to run and who asked, are written to the SecurityInsight database first, and the
  execution reads them when it begins. A start that fails is closed and never runs later. Starting a job keeps
  needing only the right to start it.

## v3.0.1 — more of SecurityInsight in the Community edition, and signed updates

The first public release of SecurityInsight 3. It is installed beside 2.2 - see "Coming from 2.2.x" under v3.0.0 below.

### More in the Community edition

- **Cross-engine correlation** (one object id across all engines) and **full asset properties** are now part of the
  Community edition. The v3.0.0 table below lists them as Pro; from 3.0.1 they are in both editions.
- **Asset tagging**, **verification** and **data health** are in both editions.
- The Community edition shows its own logo in the web app.

### Updates

- A Community install updates from the SecurityInsight update channel. Before anything is installed, the release is
  checked against a signed entry: its version, its size and its SHA-256.
- An update never overlaps another update that is still running, and a running update keeps reporting its stage, so it never looks hung.
- Version numbers are short: 3.0.1, 3.0.2, ...

### Reliability

- When a part of the data sync fails (for example because the database is full), the run reports that part as failed instead of finishing as if all was well.
## v3.0.0 — two editions, one-command updates, and your settings finally win

SecurityInsight 3.0 is the first release with two editions, a new licence for the public edition, and a
signed update path. It also fixes a long-standing
configuration bug that silently ignored some of the settings you set. **Coming from 2.2? There is no upgrade:**
SecurityInsight 3 is installed beside 2.2 - see "Coming from 2.2.x" below.

### Two editions

| | **Community** (this repository) | **Pro** (licensed) |
|---|---|---|
| Asset profiling, Risk Analysis, Risk Score, reports, executive summary | ✅ | ✅ |
| Trend, CMDB enrichment from a CSV, AI classification, Shodan, asset tagging | ✅ | ✅ |
| Cross-engine correlation (one object id across all engines) and asset properties | — | ✅ |
| ServiceNow CMDB connector | — | ✅ |
| Vulnerability close-loop to ServiceNow or a SQL database | — | ✅ |
| Updates | this repository | managed, ring-based rollout |

The Community edition is complete on its own and never contacts a licence server. Without a licence, a
Pro component prints one line saying so and publishes nothing; everything free runs as before.
Pro is available from Invardia -- [pricing](https://invardia.com/pricing/), [buy](https://invardia.com/order/), [60-day Pro trial](https://invardia.com/trial/); licensed customers get support at
[support@invardia.com](mailto:support@invardia.com) or [portal.invardia.com](https://portal.invardia.com/) › Support. Contact: [info@invardia.com](mailto:info@invardia.com).
Invardia – a brand of 2LINKIT, founded and owned by Morten Knudsen.

**Licence:** from 3.0.0 the Community edition is licensed under the **PolyForm Shield License 1.0.0** — you
may use, modify and run it, including commercially inside your own organisation, but not to provide a
product that competes with it. Every version published before 3.0.0 remains under the MIT License.

### Status reports (telemetry) — on by default, one setting turns them off

From 3.0, each install sends Invardia one status report a day (product, edition, version, hosting type, the *kind*
of sign-in identity, licence state) and one short report per engine run (which engine, ok / warning / failed, how
long it took, the stage that failed and the *kind* of error, e.g. `graph-403` or `throttled`). The **Community**
edition reports **anonymously**: a random install id kept on the machine — no tenant id, no host name, no company,
no error text, and counts only as ranges (`1k-10k`). **Pro** reports are identified by the install's key, so failed
or silent runs can be spotted before you call; their error text is shortened and cleaned before it leaves. A report
that cannot be sent never fails or slows a run. **To opt out**, set `$global:SI_Telemetry_Enabled = $false` in
`config\SecurityInsight.custom.ps1` (or the environment variable `SI_TELEMETRY_ENABLED=false`) — nothing is sent at
all then.

### SecurityInsight Pro: licence and updates from Invardia by themselves — on by default, each one setting turns it off

A **Pro** install now does two things with Invardia by itself, every night, through its updater job. The
**Community** edition is not affected: it never asks for a licence and keeps updating from this repository.

- **Automatic licence request.** When the install has no licence, the licence ends within 30 days, or it is in its
  grace period, the updater job asks Invardia for one, checks the licence it receives and installs it. The result —
  installed, or why not — is recorded in the audit trail and mailed to you (the same recipients as the safety-check
  mails). While the licence is valid nothing is asked and nothing is sent. **To turn it off**, set *Automatic
  licence request* (`SI_LicenseRequest_Auto`) to off on the web app's Settings page (or `SI_LICENSE_REQUEST_AUTO=false`
  on the updater job); renew the licence by hand then.
- **Pro updates from Invardia.** The updater job checks Invardia for the release approved for your install's update
  ring, verifies its signature and contents, and applies it — restoring the previous version if anything fails. A
  release that needs a manual step first is held and shown on the Settings page. **To turn it off**, set *Pro updates
  from Invardia* (`SI_InvardiaUpdate_Enabled`) to off (or `SI_INVARDIA_UPDATE_ENABLED=false` on the updater job); the
  install then stays on its current version.

Both are on by default — there is nothing to opt in to. The first run
after the update explains both once, with these switches; the Settings page says when either is off.

### What is new

- **The Detailed report is now the default; the Summary report is optional.** Every summary view (per recommendation
  with its affected assets, per asset, per tier, per domain, category and subcategory, per risk rating, per department)
  is now built from the detailed findings, in both editions, and the Summary step of the daily pipeline is switched off
  unless you changed your pipeline yourself (you can switch it on again under Operations > Jobs). **Installs that showed
  the Summary risk score now show the Detailed score -- it counts findings, not distinct assets -- so the number changes
  once.** The daily trend, the management summary and the mail's management summary follow the Detailed report, and the
  Summary mail recipients receive the Detailed report's mail instead.
- **Every Risk Analysis report has the same structure, and its output names are pinned.** Each report now ends in a
  generated block that lists its output columns and the SecurityInsight fields they fill; a column name is never renamed
  or removed (integrations keep working). The two Defender for Cloud recommendation reports are now split into slices on
  large tenants like every other report. This changes the internal fingerprint of every report once; SecurityInsight
  recognises it as the same report, so **no finding is closed, reopened or marked as fixed because of this update**, and
  first-detected dates and history stay as they were (also in ServiceNow and the SQL hand-off).
- **A finding never closes because a data source went silent.** Each Risk Analysis run now counts the Defender and
  Sentinel tables its reports read (one light count per source, before the reports run). When a table that had rows
  returns none, every report that reads it -- also only to look something up -- is marked *not complete*: it keeps its
  last complete result and none of its findings is closed or marked as fixed. The run says so every time, with the table,
  its last count and date, and the reports held, until the table has rows again. A table that was always empty (a feature
  you do not use) changes nothing, and a report that drops to zero while its source still has rows closes as usual.
  **If you retired that feature on purpose**, an Admin can switch the affected reports off (Reports > the report >
  *Report it*). If the count itself cannot be made, a report is held only when its own source count went from rows to none.
- **A report held at its last result no longer stops the run from being shown.** When SecurityInsight keeps a report at its
  last complete result on purpose -- a data source it reads went silent, or the Entra role read was not complete -- the run
  is still published: every other report shows the new result, the held report shows its last complete result, marked
  *not complete* with the reason, and none of its findings is closed. The run log says so by name ("published, 2 report(s)
  held at their last complete result: ..."). A report that really failed still keeps the whole run from being shown, as
  before, and the message now names that report.
- **SecurityInsight Pro: an update brings its database changes with it, before anything else.** The updater job now
  applies the new version's database tables and columns (additive only: nothing is ever removed or rewritten) and the
  database rights the web app needs, and only then rolls the new version. If the database step cannot be done, the
  update stops before changing anything, your installation keeps running the version it ran, and the reason is shown
  in Operations > Guards and mailed to you. **What an existing Pro install needs, once:** give the updater's identity
  the database rights the updater needs on the SecurityInsight Pro database (see the setup guide). Until then, updates
  wait and say why.

- **The updater job updates itself too.** After the engine jobs, the web app and its MCP server are on the new version
  and healthy, the updater moves its own job to the updater of the same version, as the very last step. The run that
  does it finishes as it started; the next run starts on the new updater. If that last step cannot be done, your
  installation is still updated and the update counts as successful: the updater keeps its current version, the update
  status says why, and the next run tries again. To keep the updater on its current version, set
  `SI_UPDATER_SELF_UPDATE=0` on the updater job.

- **Building the container images works from a deep folder on Windows.** An installation in a long folder path could
  not build its images (the build tool cannot read file paths over 260 characters on Windows). The build now runs from
  a short temporary copy when the path is too long, and the images are the same.

- **SecurityInsight Pro: the ServiceNow hand-off carries the data sensitivity.** The CI import view
  (`snowstage.vImportCi`, in the Pro database and in a SQL CMDB hand-off database) and the Import Set push have a new
  last column, `u_data_sensitivity`: the value SecurityInsight weighs risk with, where your own asset-profile rule's
  override wins over the CMDB record. Every existing column is unchanged and in its place, so your data source and
  transform map keep working; map the new column in your transform map if you want it in the CMDB (the connector page
  and the design guide describe how), or leave it unmapped. The Pro database gets the column with the update's
  database step (or by re-running `setup\Initialize-SIDataSql.ps1`); until then everything else is handed over as before.

- **SecurityInsight Pro: each Risk Analysis report now shows its own figures by default.** Summary counts distinct assets, Detailed counts individual findings, and the web app's Summary / Detailed switch shows each report's own risk score, table and Top-50. To keep both mails on the same figures as before, set *Summary and Detailed agreement* (`SI_AISummary_Mode`) to `Consistent` on the Settings page. The Community edition is unchanged (`Consistent` stays its default), and a value you have already set wins in both editions.

- **The daily jobs run as one pipeline of three stages: Collect, Correlate, Deliver.** Collect gathers the data and
  runs Risk Analysis, Correlate links the same asset seen by several sources, and Deliver hands the results on (the SQL
  data, ServiceNow, the vulnerability connectors, the mails). Each stage starts when the one before it has finished
  and succeeded, so nothing is delivered from a collection that did not complete; inside Deliver a failed
  vulnerability connector no longer stops the data sync or the mails. The pipeline starts at **22:00 in your own time
  zone** (summer time included) and the time and time zone can be changed. **Run now** works on the whole pipeline,
  on one stage or on one step, and nothing ever runs over anything else: a run that finds another one going waits in
  a queue (shown on Operations > Jobs, where it can be cancelled) and starts right after. An existing job flow is taken
  over automatically and keeps its start time. The risk trend is no longer a separate daily job: Risk Analysis writes
  the day's trend row itself.

- **You can always see which version and build you run.** The version and build are shown in the web app footer and every log: the web app shows `v3.0.0` for a release and `v3.0.0-rc.12` for a pre-release build, and every job, launcher and the installer print the version with its build at the start.

- **Defender for Cloud recommendations and vulnerabilities (CVEs)** are collected by the azure engine
  directly — including those the Exposure Graph does not carry — into their own table, and feed two new
  Risk Analysis reports. On by default; `$global:SI_CollectDefenderRecommendations = $false` opts out.
  Defender writes its remediation steps as HTML; SecurityInsight stores them as readable text, links kept.
  A finding on a VM is scored by what the machine is: a vulnerability on a domain controller is tier 0 even
  when the VM carries no criticality tag, and a subscription-wide finding takes the subscription's most critical
  resource.
  Every Azure recommendation now carries a tier, also on a VM the Exposure Graph names by its full DNS name.
  A Defender for Cloud recommendation on a virtual machine is listed once. It was listed twice -- once
  under the machine name and once under the Azure VM name -- so a server appeared twice in the top 50.
- In a tenant with several data collection endpoints of the same name, every engine now posts through the
  endpoint its rule is bound to and creates new rules on your configured endpoint, and run-health records are saved.
- **Trend** in the Community edition: a small daily rollup of your Risk Analysis results, kept for years. The Risk
  Analysis **Summary** run writes the day's trend row itself, from the rows it has just published, so there is nothing
  to schedule. A partial run is not a trend point: that day is a gap, never a drop.
- **Asset tagging is report only by default.** It is the one engine that *can* write (Defender machine tags, Azure
  resource tags, Entra custom security attributes). A run now logs every tag the rules would set and changes nothing;
  it writes only when you ask: `-Apply` on a run, or `$global:SI_AssetTagging_Apply = $true` in
  `config\SecurityInsight.custom.ps1`. `-WhatIfMode` still works (it means report only, and wins over `-Apply`), and
  `WhatIfMode = $true` in your configuration still means report only. Writing also needs the write grants
  (`setup\Grant-SIIdentity.ps1 -Tagging`, or the Tag Contributor role setup grants only when you tick "Also allow
  asset tagging").
  This holds for **every way the tagging is started**: every launcher, and the engine started directly
  (`engine\asset-tagging\AssetTagging.ps1`, which now takes `-Apply` and `-WhatIfMode` too).
- **Managed identity is the default sign-in.** The container jobs, the web app and the updater sign in with their own
  managed identities.
- **Updates come through a signed, staged release channel.** The updater takes only the release approved for your
  install's **update ring** (ring 3, broad, by default; ring 2, early release, by choice), checks its signature against
  the update key the installed version ships with, refuses an older or replayed release, and checks that the download
  is exactly the signed one (size and SHA-256). It then builds the new images in your registry and moves your jobs to
  them, restoring the previous version if anything fails. A release that needs a manual step first, or a newer
  starting version, is **held** and says why.

### Container hosting

- **Every non-secret setting in your config now reaches the container jobs.** A container never reads your
  config file; until now each setting needed its own mapping and most had none. Secrets still travel only as
  job secrets.
- **Azure OpenAI and a storage account key are no longer required.** Without a key, the jobs use their own
  identity (OAuth); without OpenAI, they run without AI classification.
- **The Shodan key reaches the public-IP job.** It did not before, so public IPs were collected without
  Shodan enrichment while the run reported success.
- **Trend:** the trend job is created next to the other jobs (09:00 UTC by default). When your jobs run as one
  pipeline it has no timer of its own — Risk Analysis writes the day's trend row — and it stays runnable by hand.
- **Setup now remembers where your containers live**, so every later update finds them.

### Fixes

- **Your own asset-profile rule now wins over the CMDB record.** When a rule maps assets to a CMDB service and also
  sets `cmdbName`, `cmdbCriticality` or `cmdbDataSensitivity`, the rule's value is used for those assets instead of the
  CMDB record's, field by field — before, only the service id was taken from the rule. The profile tables record
  where each value came from (`CmdbNameSource`, `CmdbCriticalitySource`, `CmdbDataSensitivitySource`), the weighted
  risk score follows the effective values, and SecurityInsight Pro's CI table and ServiceNow hand-off carry them too.
- **Settings in `config\SecurityInsight.custom.ps1` now override the shipped per-engine defaults** — as
  the samples and documentation always said. Before, the shipped defaults loaded *after* your file and
  silently replaced about 60 settings, among them the export destination, the bucket cap, the output
  sinks, forced full runs and the Defender workspace.
- A tier cadence written as a bare number (`$global:SI_TierCadence_T3 = 336`) now means hours. It used to
  fall back to one day, so low-tier assets were re-classified daily.
- The Risk Analysis launchers honour the report-template settings the configuration reference documents.
- Risk Analysis correctness: a hunting query that times out now fails loudly instead of returning a partial
  result; findings lost in adaptive bucketing are accounted for; the report's row count is checked against
  what was ingested; mail sender, number and date formatting (also on non-English hosts), the AI summary
  timeout, the Top-50 ordering and the weight columns were corrected.
- Asset profiling: dates on PowerShell 7 and non-English hosts, enrichment keys, silent under-collection,
  storage access, the Shodan monthly cap and its cache, Log Analytics type handling and Resource Graph paging
  were corrected.
- Trend: the "Tier-0 assets with findings" figure — and every other asset count in the trend (per severity, tier
  and domain) — now counts assets. It used to count the kinds of finding, so one machine with three problems
  showed as three and a vulnerability on twenty machines showed as one. Trend points recorded before this
  update keep the old figure.
- Trend: the weekly opened and closed figures now count every affected asset — a vulnerability on three
  machines counts three — so from this update they rise compared with earlier weeks.
- **Azure recommendations no longer go missing when the Exposure Graph loses a recommendation's own entry.** The
  graph can keep the link from a recommendation to a resource after the recommendation itself has left it; such a
  recommendation (for example "Public network access on Azure SQL Database should be disabled", or "Audit flow logs
  configuration for every virtual network") was dropped from the Azure recommendations reports although Defender for
  Cloud still lists it as unhealthy. It is now reported from the link itself, with Defender for Cloud's severity. The
  hand-off to the Defender for Cloud recommendations report also matches on Defender's own assessment, so a
  recommendation the two sources name differently is listed once. Expect these reports to grow on their next run.
  SecurityInsight Pro: the change ships as template pack 1.3 (Template releases).
- **The CVE reports see every vulnerability Defender lists.** `Device_Missing_CVEs_*` read only the vulnerabilities
  the Exposure Graph links to a device — about two in three. They now also read Defender Vulnerability Management
  directly, so a device with vulnerabilities but no graph link is no longer missing. Expect these reports to grow.
- **A split Summary report keeps every asset.** A large Summary report that is divided into parts kept the assets of
  one part only, so the devices with the most findings could be missing from it. Expect more Summary rows.
- **One machine has one tier everywhere.** A machine seen by several sources (Entra, Defender, the Exposure Graph,
  Azure) is one asset with one tier and one name in every report; before, each source could give it its own tier.
- Endpoint profiling: devices that share one name in Defender — for example devices Defender lists without a real
  computer name — are now each profiled under their own Defender device id. Before, they were merged into one asset
  and which device it described changed from run to run, so its findings appeared as "new" on one run and "no longer
  reported" on the next while the other devices were not profiled at all. The endpoint asset count can rise by the
  number of such devices. Devices with a unique name are merged across sources exactly as before.

### Coming from 2.2.x

There is no upgrade from 2.2 to 3.0. SecurityInsight 3 is a separate installation: it runs in Azure Container Apps
with its own SQL database and web app, signs in with managed identities and keeps its settings in the database. Install
it beside 2.2 with the guided install, in its own resource group (default `rg-si`), run both while you compare the
results, and switch 2.2 off when you are ready. 3.0 does
not read or change anything of a 2.2 installation, and a 2.2 installation is never updated to 3.0.

Every step - what you need, the install, running both, what you carry over by hand and what to remove when you retire
2.2 - is in [SecurityInsight 3 beside 2.2](https://invardia.com/docs/securityinsight/side-by-side/).

---

SecurityInsight 3 replaces SecurityInsight 2.2; the 2.2 release history is not part of these notes.
