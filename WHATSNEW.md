# What's new in SecurityInsight

## 3.1.53 · 2026-11-26 · Fix-only

No more false "not refreshed" warning, exports read one consistent picture, and updates started by hand go through.

### New features

None in this version.

### Fixes

- **No false recommendations warning** - The run report no longer says the Defender for Cloud recommendations were not refreshed when they were.
- **Partial results said as not complete** - When a Defender for Cloud result was not read in full, the reports that use it say it is not complete, and nothing is closed because of it.
- **Consistent exports** - Exports read one consistent picture while data changes; an export whose rows changed while it ran is refused, never handed out mixed.
- **Updates started by hand go through** - An update started by hand close to a scheduled update time is no longer ended early.
- **Smaller fixes** - The identity-names report is stored whole, support sees the last run per step and the image clean-up, and large exports continue on a second sheet.

## 3.1.52 · 2026-11-26 · Feature update

Large installations finish their runs, a warning shows when data is old, and the 3.1.51 data corrections.

### New features

- **Old data is flagged** - When an installation's newest data is older than 36 hours, a warning shows the age and the last run's result: on every page for Admins, on Home and the wall board for readers.

### Fixes

- **Large installations finish their runs** - The Detailed CVE report, profiling and reading recommendations no longer run out of memory at large installations; a failed recommendations refresh is reported. A yes/no property stored as "False" now reads as no, so some identity properties change once.
- **Updates finish and clean up** - An update in a long database step is no longer stopped as having no sign of life. It removes references to deleted managed identities, so new jobs can be created again, and afterwards only the current web app version answers.
- **Data corrections** - Azure resources moved between resource groups are no longer retired; any retired come back by themselves. Software update tasks update once. Scope rules also match long product lists, so some rules match more findings once.
- **Exports include every row** - Exports include every row, with no 50,000-row limit. An export whose data changed while it ran is refused, never cut short.
- **Smaller fixes** - The statistics refresh is no longer re-created on each update; the privileged-identity tier no longer says complete when Log Analytics was unreadable; export column titles name their field; capped software lists hold tasks open, with ServiceNow field u_si_software_lists_complete.

## 3.1.51 · 2026-11-25 · Feature update

Job buttons work again, deleted assets retire at once, exploited findings are due in 14 days, and tiles and columns say what they show.

### New features

- **Deleted assets retire at once** - An asset deleted in Entra ID, Azure or Intune retires at once and its findings close as deleted, never as fixed. Intune needs one new read-only permission that Invardia grants.
- **Pages load their newest scripts** - After an update every page loads its newest scripts; a page that cannot load shows a Reload link.
- **Exploited findings due in 14 days** - A finding whose exploit is verified, or that is in an exploit kit, is due within 14 days, whatever its severity.

### Fixes

- **Job buttons work again** - Buttons that run a job (one step, Refresh, Run now, Update now, Apply settings, Test mail, Send now) work again. A cancelled run no longer reports its last step as failed.
- **Tiles and columns in plain words** - The executive tiles say what they count, with the formula and an (i). Column titles are in words, exports included: scripts reading old header names need updating.
- **New days-to-fix defaults** - Medium findings 60 days, low findings 90 days, so some may show as overdue sooner. Your own values and Defender for Cloud due dates are kept.
- **One task per product and version** - A vulnerability naming several products gives one task per product and version, each with its own paths.
- **Smaller fixes** - Sign-in methods per user fill in again at every installation. Asset profiling builds its rows 5-7 times faster. Views are compact, with resizable columns and full text.

## 3.1.50 · 2026-11-25 · Feature update

The job buttons go through a queue, Remediations pages answer faster, and profiling rules are grouped by kind.

### New features

- **Profiling rules grouped by kind** - Configuration > Profiling rules lists the rules in collapsible groups, one per kind of condition.
- **Tasks follow Defender's remediation type** - A Defender recommendation's task follows Defender's own remediation type.

### Fixes

- **The job buttons go through the queue** - Run now, Stop, schedule changes, template release and mail send-now go to the installation through a queue.
- **Faster Remediations pages** - Task report values are kept ready and statistics are refreshed after each data sync, so the first click answers quickly.
- **One finding per recommendation and CI** - Defender for Cloud and the Exposure Graph reporting the same recommendation on one CI give one finding.
- **Domain and category owners recognised** - Owners named by e-mail address are looked up once and stored, so they can decide their requests.

## 3.1.49 · 2026-11-25 · Feature update

Duplicate recommendations are merged into one finding, and each task sent to ServiceNow carries its full context.

### New features

- **Full task context to ServiceNow and SQL** - Each remediation task carries what to do first, paths, the recommended update, CVE ids, risk, due date, the asset and a link to its page. Add the new columns from the connector page's table definition.
- **Duplicates not merged are shown** - Operations > Data quality shows duplicates not merged, and the run log warns with examples.

### Fixes

- **Duplicate recommendations are merged** - An 'Update <software>' recommendation for software whose CVEs are already on the asset becomes evidence on those CVE findings ('Also reported by').
- **A merged recommendation closes as 'Linked'** - It is sent to ServiceNow and the SQL hand-off as closed 'Linked' to the CVE finding, never as fixed and never dropped.
- **The job buttons work again** - Run now, Stop, schedule changes, template release and mail send-now go to the installation through a queue.
- **Support access answers each request in turn** - A support session's close no longer cancels another session's waiting request.
- **Guests are recognised again at sign-in** - Guests kept by e-mail address are looked up once and stored, with no object id to enter by hand.

## 3.1.47 · 2026-11-25 · Feature update

Each remediation task has its own page.

### New features

- **A page for every remediation task** - Each remediation task has its own page: what to do, the application, its version and every path, the asset, the dates, and every finding behind the task, with export.

### Fixes

- **Signed requests show local times** - The signed requests page shows its times like every other page.

## 3.1.46 · 2026-11-25 · Feature update

The protection score now gives credit for every fix, and its formula is shown next to it.

### New features

- **The protection score gives credit for every fix** - Each asset has a health of 0-100: Very High -25, High -10, Medium and Low together at most -20. Tiers count with fixed shares: Tier 0 40 %, Tier 1 30 %, Tier 2 20 %, Tier 3 10 %.
- **The formula next to every protection score** - The formula, with your own settings, is shown next to every protection score on the Executive overview, the Executive report and the wall board.

### Fixes

- **Application columns right after the task** - On Remediation tasks, Application, Application version, Paths and Detected paths sit right after the task, also in saved layouts.
- **Support access closes when it should** - A request to close support access always goes through, also when several requests wait at once.
- **The update shows its progress** - A long refresh of the pages' data during an update says how far it has come, and a finished update is no longer reported as stopped.
- **Summary groups keep one spelling** - A value spelled two ways (User and user) is one group, so the history check no longer reports false differences.

## 3.1.45 · 2026-11-24 · Feature update

Security recommendations Summary and Detailed can show only the risks past their accepted time to fix.

### New features

- **Actual Risks or Within Accepted Lifecycle** - Security recommendations Summary and Detailed have a choice above the table: Actual Risks (the default, every open finding) or Within Accepted Lifecycle (only findings past their accepted time to fix). The wall board's table uses the same choice.

### Fixes

None in this version.

## 3.1.44.2 · 2026-11-24 · Fix-only

The finding history writes only what changed; bundled applications get their own tasks; disabled service principals are handled like disabled users.

### New features

None in this version.

### Fixes

- **Finding history writes only what changed** - A finding that did not change keeps its state, so each run records only new, changed and closed findings.
- **Bundled applications get their own tasks** - A library bundled in several applications is one task per application, named after its install folder, with full paths and the application version.
- **Disabled service principals handled like disabled users** - A disabled service principal no longer counts as a vulnerable asset, even with high privileges.

## 3.1.44.1 · 2026-11-24 · Fix-only

The vulnerability close-loop step runs again, and security image updates arrive within 15 minutes.

### New features

None in this version.

### Fixes

- **Vulnerability close-loop runs again** - The close-loop step reaches its database again; a check now makes sure every step can load what it needs.
- **Security image updates within 15 minutes** - Every installation checks for newer security images every 15 minutes and applies them without stopping a run.
- **Release checks run first** - The quick release checks and the ring check run before the tests, so a problem is found in seconds.

## 3.1.44 · 2026-11-24 · Feature update

Large installations finish their runs much sooner: results are prepared as they arrive, only what changed is worked out again, and every run checks itself.

### New features

- **Only what changed is worked out again** - Findings are stored ready to show, and the data sync and the vulnerability connector work on what changed. Every run also checks a rotating seventh of the assets in full.
- **Finding history** - Each run is kept as finding states and checked every run. Pages and connectors read it only when that run was verified.
- **Totals from what changed** - Key figures and summary groups are worked out from what changed and compared with a full build every run.
- **Faster data sync and vulnerability report** - The data sync starts per report and loads in checked batches; the vulnerability report asks Defender in parallel within its limits.
- **Faster on large installations** - Old collections leave the database in one step, and the largest tables get columnstore indexes built when the installation is not busy.

### Fixes

- **One unreadable report no longer holds the run** - A report that could not be read because of a passing service problem shows its last complete result, marked with its date.
- **Parallel loading no longer blocks itself** - Risk Analysis workers loading findings at the same time no longer wait on each other.
- **Time limits on Azure reads** - Each Azure read has a time limit and a progress line each minute; a read that gives up is marked unknown, never empty.
- **Smaller fixes** - Mail can be set up through the update; the database load and a size recommendation go to support as numbers only.
- **First run after the update builds in full** - The first run after this update builds everything once in full; the runs after it are the faster ones.

## 3.1.43.5 · 2026-11-23 · Fix-only

The Azure collection no longer waits silently on Defender for Cloud.

### New features

None in this version.

### Fixes

- **Azure collection no longer waits silently** - Each Defender for Cloud read now has a time limit, every retry is logged and a progress line appears each minute. A read that still gives up is marked unknown for that subscription, never shown as nothing found.

## 3.1.43.4 · 2026-11-23 · Security

Security update of the base images.

### New features

None in this version.

### Fixes

- **Security updates for the base images** - SecurityInsight's containers are rebuilt on Microsoft's newest base images. Microsoft published security fixes for the .NET and Ubuntu base images SecurityInsight builds on; this release moves to them.

## 3.1.43.3 · 2026-11-23 · Security

Security update of the base images.

### New features

None in this version.

### Fixes

- **Security updates for the base images** - SecurityInsight's containers are rebuilt on Microsoft's newest base images. Microsoft published security fixes for the .NET and Ubuntu base images SecurityInsight builds on; this release moves to them.

## 3.1.43 · 2026-11-21 · Fix-only

AI switched off is off everywhere, and a run never fails because the AI connection is missing.

### New features

None in this version.

### Fixes

- **AI off wins over every AI switch** - With AI switched off for your installation, no engine, no AI summary and no tier catalog build uses AI, whatever their own switches say.
- **No failed run without an AI connection** - When the AI summary is on but the Azure OpenAI connection is not set, the run says so once and builds the Top 50 lists without the summary.
- **Support can switch AI off** - Support can switch the AI summary and each engine's AI switch off for your installation through the nightly update, never on.

## 3.1.42 · 2026-11-21 · Feature update

The attack-path reports to Azure complete at the largest installations: every part is answered from the graph stored once per run.

### New features

- **Alert at the AI daily limit** - When the AI daily limit is reached, Invardia receives an alert as well as the warning in the run log, so support sees it at once.

### Fixes

- **Attack-path reports use the stored graph** - The two reports on devices with high-severity vulnerabilities that allow lateral movement to Azure answer every part from the graph SecurityInsight stores once per run, so they complete at the largest installations.
- **AI roles left alone while AI is off** - With AI switched off, the update leaves the Azure OpenAI roles of the engine and web identities alone and does not mention them.

## 3.1.41 · 2026-11-21 · Feature update

AI is off unless you switch it on, asks only about what changed, and stops at a daily limit you set; a stuck pipeline step no longer holds an update.

### New features

- **AI daily limit** - Configuration > Settings > AI has a daily limit in tokens, next to the AI switch, with what it costs per day. At the limit SecurityInsight sends no more AI requests that day and tells you once.
- **AI asks only about what changed** - With AI switched on, an asset is asked about only when the facts that decide its answer changed, 25 assets per request, with only those facts. Raw device data is never sent.
- **AI is off by default** - Every AI feature is off until a person switches it on in Settings, in both editions.
- **A stuck step no longer holds an update** - A pipeline step that has written nothing for far longer than it usually takes is stopped and reported, and the update follows when the run has ended. A step that still writes progress is never stopped.

### Fixes

- **The update moves itself early again** - The update's first step, pointing itself at the new release, works again instead of waiting until the end of the update.
- **AI requests are not repeated** - An AI request is tried at most twice, and a request the service refuses is not sent again.

## 3.1.40 · 2026-11-20 · Security

Every change in the web app is checked against the signed sign-in of the person who made it; Access and History are in both editions.

### New features

- **Signed changes** - The engine checks the signed sign-in of the person behind every web app change before it acts. SecurityInsight first only observes; once a SuperAdmin adopts the configuration on Configuration > Signed requests, an unverified change is held and explained.
- **Access and History in both editions** - Configuration > Access (roles and scopes for people and groups) and Configuration > History (the audit trail) are part of the Community edition too. Every security control is the same in both editions.
- **Narrower database rights, step by step** - Support can narrow each component's database rights to exactly its job, through the nightly update: first a plan that changes nothing, then the change, read back, and a way back.

### Fixes

None in this version.

## 3.1.39 · 2026-11-20 · Feature update

Defender for Cloud findings are read from two sources, so none go missing; long data syncs finish reliably.

### New features

- **Defender for Cloud read from two sources** - SecurityInsight reads your Defender for Cloud findings both from Azure Resource Graph and from Defender for Cloud itself, per subscription, and combines them. Findings that one source stops returning are still read from the other.
- **Support can load a licence edition** - Support can request a licence edition for your installation, or switch back to the previous licence, through the nightly update. Only a licence signed for your own tenant is ever installed.

### Fixes

- **New vulnerabilities counted correctly in data health** - Data health counts a vulnerability that Defender reports on a device after a collection as new, not as missing from SecurityInsight.
- **Long data syncs finish** - A long data sync keeps a valid sign-in to the database for its whole run, and a short service fault in Log Analytics is retried instead of ending the step.
- **Every failed run names its cause** - Each failed run reports a stable code that says what happened, so support sees the cause at once.
- **Collection picker and Findings page** - The collection picker shows each run's time and rows only, and the Findings page lists only the runs whose findings are kept.
- **ServiceNow checks of the task tables** - The ServiceNow check of the remediation task tables checks the connection, the table and its columns, without a false warning about measuring them.

## 3.1.38 · 2026-11-19 · Feature update

Support can switch off a report whose data source your licence does not include.

### New features

- **Reports switched off by support** - When a report's data source is not part of your licence, support can switch that report off for you, the same way an Admin does under Reports. The change is in the change log with who asked and why.

### Fixes

None in this version.

## 3.1.37 · 2026-11-19 · Fix-only

The Findings page lists only the runs whose findings are kept.

### New features

None in this version.

### Fixes

- **Findings lists only kept runs** - The Findings page's collection picker lists only the runs whose findings are kept (the newest 3 by default), like every view.

## 3.1.36 · 2026-11-19 · Fix-only

The collection picker no longer says older data.

### New features

None in this version.

### Fixes

- **Collection picker without older data** - The collection picker shows each run's time and rows only; Run health > Reports lists every report of the run.

## 3.1.35 · 2026-11-19 · Fix-only

Task views open from every task report; the older-data note is gone from the pages.

### New features

None in this version.

### Fixes

- **Task views open from the task reports** - Opening Tasks per asset or Task findings from a task report (a product, a group, an action) shows the tasks with their detected paths.
- **No older-data note on the pages** - When some reports of a run show older data, the pages no longer show a note about it; the collection picker still says older data, and Run health > Reports lists every report.

## 3.1.34 · 2026-11-19 · Fix-only

Task views show where a product was detected and every task column; the standard filter; Verify on the ServiceNow connector works again.

### New features

None in this version.

### Fixes

- **Where it needs fixing** - Tasks per asset and Task findings show the detected paths: where the product was found on the asset. Every task column is shown by default.
- **One filter on the task views** - The task views filter with the grid's own filter, like every other view. The task reports' filter is one compact row, and the note about reports with older data is one slim line.
- **Verify on the ServiceNow connector** - Verify starts the ServiceNow check again: SecurityInsight's pipeline job starts it within 5 minutes, and the result shows on the connector page.

## 3.1.33 · 2026-11-19 · Security

Microsoft's newest base images, and the earlier sign-in component removed.

### New features

None in this version.

### Fixes

- **Security updates for the base images** - The engine, the updater, the web app and the MCP server are rebuilt on Microsoft's newest .NET base images, with Microsoft's latest security fixes.
- **Earlier sign-in component removed** - Every installation signs in with Microsoft's built-in sign-in. The separate sign-in component that came before it is no longer carried, built or offered.

## 3.1.32 · 2026-11-18 · Feature update

Remediation tasks for IT operations, linked everywhere, and complete attack-path reports at the largest installations.

### New features

- **Deploy once, fix many** - Remediations > Task reports shows each action across all assets: the assets it covers, the risk and CVEs it removes, and the tool that fits (patch tool, software deployment, policy, Azure, manual). Actions on many assets come first.
- **Task reports by product, owner and service** - Group open tasks by product, tool, owner, department, IT service, OS or age, see what no mass deployment fits, and follow tasks opened and fixed per week. Filter by IT service, OS version, risk rating, category and more.
- **Top 50 actions in the management report** - Chapter 6 "Remediation" shows the open tasks, what was fixed since the last report, the work per tool and the top 50 actions -- on the page, in the PDF, in the mail and in the presentation pack.
- **Tasks on the asset pages** - The asset and CI pages show the asset's remediation tasks, a finding shows the task it belongs to, and an asset name opens the asset page with its linked objects.

### Fixes

- **Every finding on the CI page** - The CI page's findings lists no longer stop at 500: they page through every finding and show the true totals.
- **Attack-path reports complete at large installations** - The reports on devices whose vulnerabilities allow lateral movement to Azure read Microsoft's attack-path data once per run, so they no longer time out at the largest installations. The rows are the same as before.

## 3.1.31 · 2026-11-18 · Fix-only

The Tasks view shows each task's own columns, next to the vulnerability's columns.

### New features

None in this version.

### Fixes

- **Task columns in the Tasks view** - Remediations > Tasks per asset shows Paths, Closed, Reopened, Highest weighted risk and Security domain by default, next to the other vulnerability columns. A layout you saved yourself stays; reset the layout to get the new default.

## 3.1.30 · 2026-11-17 · Feature update

Remediation tasks per asset, ready for ServiceNow, and more reliable attack-path reports.

### New features

- **Remediation tasks per asset** - Findings are grouped into tasks on each asset: an update, a software upgrade per version, a bundled library (with all its paths), or a configuration change. See Remediations > Tasks per asset; a task opens its findings. Both export.
- **Tasks to ServiceNow** - Two new ServiceNow outputs send the tasks and their findings once their Import Set table names are entered on the ServiceNow data-out connector page.
- **Verify table schema checks every table** - The ServiceNow connector page checks each table's columns: present, missing, too short or the wrong type, and which new columns can be switched on.
- **More ServiceNow fields for vulnerable items** - 14 more fields, such as security domain, category, risk score, tier and the fix KB, can be switched on per column under Connectors > Fields sent.
- **False positive on this server** - An Admin can mark a software detection as a false positive for one server, with a reason, audited and reversible.

### Fixes

- **Attack-path reports are more reliable** - Each part of the query is sized to the back end's own time limit, and a report is marked complete only when its row count is confirmed.
- **Where software was found is kept in full** - Every software finding keeps its full path on every drive and the application it belongs to.
- **Plainer warning mails** - Data-quality notices say what happened, whether anything was lost and whether you need to do anything.
- **Leaner at large installations** - The task build, the vulnerability step and the software evidence use a fixed amount of memory at any size, with the same results.

## 3.1.29 · 2026-11-16 · Fix-only

Faster nightly runs at large installations.

### New features

None in this version.

### Fixes

- **The data sync reads each finding once** - The same results, in far less time at large installations.
- **The vulnerability step is faster** - Findings that never change a record are no longer processed, and the bulk work runs compiled; every decision is the same as before.
- **A long attack-path report shows its progress** - It is no longer flagged as not moving while it works.
- **The MCP server is closed on new installations** - It is not reachable from the internet.

## 3.1.28 · 2026-11-16 · Security

Only the images in use are kept.

### New features

None in this version.

### Fixes

- **Only the running images are kept** - After an update the registry keeps just the images in use; earlier ones are removed.
- **Unused repositories are emptied** - A SecurityInsight repository nothing runs from is emptied; other repositories are never touched.

## 3.1.27 · 2026-11-15 · Security

The right rights, set by the update itself.

### New features

None in this version.

### Fixes

- **Exactly the rights each part needs** - Unused rights are removed, rare ones are given only on demand, and the needed ones are set up and read back.
- **The web app reads no Azure details** - The System Documentation's facts come from the update, so the web app needs no read right on your resources.
- **Settings change only through the update** - A value set on the update job is applied, read back and recorded by the update itself.

## 3.1.26.1 · 2026-11-15 · Security

Tighter Key Vault rights for the web app.

### New features

None in this version.

### Fixes

- **No earlier Key Vault right** - The update removes the web app's earlier right to write secrets, read back.

## 3.1.26 · 2026-11-15 · Fix-only

AI works with the newest models, and the earlier sign-in leaves nothing behind.

### New features

None in this version.

### Fixes

- **AI works with the newest models** - The AI summary and the web chat ask the way current Azure OpenAI models expect, and adjust once by themselves.
- **The earlier sign-in leaves nothing behind** - After the switch, the update removes the earlier sign-in's images and keys, each step read back.
- **Scripts are always published unsigned** - A dormant signing path is removed, and a check keeps it out.

## 3.1.25 · 2026-11-15 · Security

Signed in all day, and updates that finish in one go.

### New features

- **Signed in all day** - The page renews your sign-in by itself before it runs out, and an expired token is never accepted.
- **The sign-in check proves itself** - Each time the web app starts, it checks Microsoft's token check on test tokens before it is used.

### Fixes

- **Updates finish in one go** - Steps that come with a new version run in that version during the same update.
- **Short hiccups are not failures** - A short network or busy moment during an update is reported as such when nothing changed.
- **No self-given AI rights** - SecurityInsight never gives itself a role on your Azure OpenAI; the unused key setting is removed.

## 3.1.24.1 · 2026-11-15 · Security

The switch to Microsoft's sign-in finishes on large installations.

### New features

None in this version.

### Fixes

- **Sign-in keys move even when busy** - Right after the switch, the move of the sign-in keys off the Key Vault waits for the web app and tries again.
- **No wrong advice about the sign-in** - An installation on Microsoft's sign-in is never told to turn it off.

## 3.1.24 · 2026-11-15 · Security

AI works without a key: SecurityInsight signs in to your Azure OpenAI resource with its own identities.

### New features

- **AI works without a key** - Turn AI on and set the Azure OpenAI endpoint and deployment. SecurityInsight signs in with its own identities, so no key is stored. Give them the role Cognitive Services OpenAI User on the resource, or ask your support partner.

### Fixes

- **The web chat follows your AI settings** - Each update gives the web chat the endpoint and deployment from your settings, and removes them when AI is off. The web app restarts only when a value changed.
- **The engines follow your AI settings** - A change of the endpoint or deployment on the Settings page reaches the engines with the next update.
- **An older key is only a fallback** - An installation that still has a key keeps working. The key is used only when the sign-in with SecurityInsight's own identity is refused.
- **Get Started no longer asks for a key** - The AI step is done when AI is on and the endpoint and deployment are set. The key field is optional and only for older setups.
- **The Azure OpenAI check script starts after sign-in** - The downloaded check script no longer stops at once when it is run after signing in with an application.

## 3.1.23.1 · 2026-11-15 · Security

New MCP clients find Microsoft's sign-in by themselves, and stop and update never stops a run it could not read.

### New features

- **New MCP clients find Microsoft's sign-in themselves** - The MCP server tells an MCP client where to sign in with Microsoft and what to ask for, so a new client connects without extra setup. You sign in as yourself and see only what your SecurityInsight role allows.

### Fixes

- **A run is never stopped blind** - When the run's record cannot be read, nothing is stopped or started, and it says how to go on.

## 3.1.23 · 2026-11-15 · Security

Every public address is behind Microsoft's sign-in, with fewer rights behind it.

### New features

- **The MCP server is behind Microsoft's sign-in** - Like the web app, the MCP server now answers only requests that carry a valid Microsoft sign-in. It still checks the token and the person's role itself.
- **Every public address is checked** - Each update lists every part of the installation that is reachable from the internet and reports any that is not behind Microsoft's sign-in.

### Fixes

- **The web app verifies who signed in** - With Microsoft's sign-in, the web app takes the person only from a sign-in token it verifies itself, never from a header alone.
- **No Key Vault access for the web app** - The web app keeps its sign-in keys in its own storage, so it no longer holds any right on the Key Vault.
- **The updater only reads group membership** - The updater no longer holds the right to change group memberships. It only checks that the database job's membership is in place and says when it is not.
- **Leftovers of the earlier sign-in are removed** - After the switch, the earlier sign-in's settings and its database tables are removed, each step read back. Anything else is reported.
- **A refused save says who refused it** - When a save is refused, the message now says whether SecurityInsight or the sign-in layer refused it, and what to do.

## 3.1.22 · 2026-11-15 · Security

Saving works again with Microsoft's sign-in.

### New features

None in this version.

### Fixes

- **Saving works with Microsoft's sign-in** - With Microsoft's sign-in switched on, saving a form was refused. The web app now tells the browser to send its own address to SecurityInsight only, which Microsoft's protection needs, so every save works again.

## 3.1.21 · 2026-11-15 · Security

Switching on Microsoft's sign-in now waits until the web app is ready.

### New features

None in this version.

### Fixes

- **Microsoft's sign-in switches on reliably** - When an update has just rolled out a new web app version, switching on Microsoft's sign-in now waits until the web app is ready instead of stopping. The account picker is always shown.

## 3.1.20 · 2026-11-14 · Security

With Microsoft's sign-in, you always choose which account to sign in with.

### New features

None in this version.

### Fixes

- **Choose the account at every sign-in** - Microsoft's sign-in always asks which account to use, so an admin account can be chosen instead of the account the browser is signed in with. The no-access pages offer to sign in with another account.

## 3.1.19 · 2026-11-14 · Security

Microsoft's own sign-in can now protect the web app, so every visitor signs in with Microsoft Entra before reaching SecurityInsight.

### New features

- **Microsoft's built-in sign-in for the web app** - The web app can sit behind Microsoft's own sign-in. Visitors sign in with Microsoft Entra before anything else, your Conditional Access applies, and no password or secret is stored. Your support partner turns it on per installation.

### Fixes

- **Group access works with the new sign-in** - With Microsoft's sign-in, SecurityInsight reads each person's groups itself, so access given to a group keeps working.

## 3.1.18 · 2026-11-14 · Security

The parts of SecurityInsight that are reachable from the internet now hold only the rights they need, and a short network fault no longer stops a scheduled wake-up.

### New features

None in this version.

### Fixes

- **The web app holds only needed rights** - The web app and MCP server identities keep only the rights for their own data, checked on every update. Until the next version, Run now, stopping a run, schedule changes and template releases show a message; scheduled runs continue.
- **Short database network faults are retried** - When the connection to the database fails for a moment while it is being set up, SecurityInsight tries again after a short wait instead of stopping the run.

## 3.1.17 · 2026-11-13 · Feature update

See what is new in every version, get security updates within the hour, and each mail goes out once.

### New features

- **What's new in the web app** - Help > What's new shows what each version brought, newest first, in plain words. A New mark appears after an update until you open the page.
- **Security updates install within the hour** - When a security update of the images SecurityInsight runs on is released, your install takes it within the hour, without waiting for the nightly update. A running job is never stopped for it.

### Fixes

- **Each mail is sent only once** - The Risk Analysis mail and the daily summary mail are no longer sent twice when a step runs again. Other queued mails also go out only once.
- **Data correlation waits for new fields** - When a data table is still taking a new field, correlation now waits for it instead of stopping the run. The steps after it then run as usual.
- **Smaller fixes** - When two collections run at once, the newer device and identity details are kept. Old records about how complete each collection was are removed with the collection.

## 3.1.16.1 · 2026-11-14 · Security

The sign-in page now runs on Microsoft's newest security updates.

### New features

None in this version.

### Fixes

- **Sign-in page security update** - The sign-in page in front of the web app now uses Microsoft's newest security fixes for .NET.

## 3.1.16 · 2026-11-13 · Fix-only

Your reports now rest only on complete data, and updates run more reliably.

### New features

None in this version.

### Fixes

- **Reports use only complete data** - When a data collection is incomplete, it no longer replaces your good history. You never see or receive incomplete data.
- **Updates finish reliably** - Long updates are no longer stopped by mistake, and the updater no longer stays behind on an older version.
- **You see when sending is paused** - When sending data to your other systems is paused because the newest data was incomplete, SecurityInsight now tells you, and since when.
- **A finished step is never started again** - A step that already ran is no longer started a second time.
- **Smaller fixes** - Mail waits safely when Microsoft cannot confirm the mailbox, and finished runs show as finished. Update logs are complete, and the identity collection is quick again.

## 3.1.15 · 2026-11-13 · Fix-only

Nothing is sent to your other systems from a run that did not finish every step.

### New features

None in this version.

### Fixes

- **Incomplete runs send nothing out** - When a step that a collection is built on fails, nothing is sent to ServiceNow or the workbooks. What they have stays, and the next complete run sends what changed.
- **Restarted runs are judged correctly** - When a run is started again from a later step, a failure earlier in that run still holds the collection back.
- **Switched-off steps never hold data back** - A step you switched off, or a step that Risk Analysis does not read, never holds a collection back.

## 3.1.14 · 2026-11-12 · Fix-only

Only data built on complete source data reaches ServiceNow and the workbooks.

### New features

None in this version.

### Fixes

- **Sending checks the data it sends** - Before sending, SecurityInsight now checks that the very collection it sends was built on complete source data. If not, nothing is sent, and the next complete run sends what changed.
- **Held sending shows as a warning** - When sending is held, the log now shows a warning with the collection's time and why it was held.

## 3.1.13 · 2026-11-12 · Fix-only

Device tiers follow privileged sign-ins, and only complete data is sent to your other systems.

### New features

None in this version.

### Fixes

- **Privileged sign-ins count for devices** - A device that a Tier 0, 1 or 2 account signs in to takes that tier.
- **One tier problem no longer spoils a run** - When one tier source fails, only that value shows as unknown on the devices, with the reason. The rest of the run is complete and goes on as usual.
- **Incomplete data is never sent out** - Nothing built on incomplete source data is sent to ServiceNow or the workbooks. What they have stays, and the next complete run sends what changed.
- **Older program images are cleaned up safely** - The clean-up of older program images no longer stops during long work. It records what it keeps before it deletes anything and reports its progress as it goes.
- **History keeps the newest 3 complete runs** - Each installation now keeps the findings of its newest 3 complete runs instead of 7. Older runs keep their totals for the trends, and the log names each run removed.

## 3.1.12 · 2026-11-12 · Feature update

You can look back a week, and heavy reports and Risk Analysis finish more reliably.

### New features

- **A week of history** - Each installation keeps the findings of its newest 7 runs, so What changed and the history pages go back a week. When the database is 70% full, SecurityInsight keeps fewer runs and tells you.

### Fixes

- **Heavy attack-path reports complete** - A report part that Microsoft keeps timing out on is now split into smaller parts, so the report completes instead of leaving parts unread.
- **The Summary view is always ready** - The Summary view is built for every collection you can open, also when a preparation step failed the night before.
- **Risk Analysis ends much faster** - The end of a large Risk Analysis is much faster, where it took hours at the largest installations. The results are the same.

## 3.1.11 · 2026-11-12 · Feature update

Your installation stays tidy, and the web app's components carry Microsoft's November security updates.

### New features

- **Older program images are cleaned up** - After a healthy update, SecurityInsight keeps only the current release's images and the one before. Nothing is deleted when the update did not end healthy.

### Fixes

- **Web app components on November security updates** - The web app's own components carry Microsoft's November security updates.
- **Security pack names the support scripts** - The security pack names the published support scripts, with their rights and changes.

## 3.1.10 · 2026-11-12 · Feature update

Devices used by privileged accounts are prioritised correctly, and every mail says where it comes from.

### New features

- **Devices take their most privileged user's tier** - When a Tier 0, 1 or 2 account signs in to a device, the device gets that tier. Devices of HR and finance accounts become Tier 2, so they are patched before Tier 3 devices.
- **Every mail names its environment** - The subject and first line of every mail start with the environment's kind and name, and the body names the tenant. You never mistake one installation's mail for another's.
- **Community and Pro work the same way** - Both editions now install, run and update the same way; only the licensed features differ. A setting is marked Pro only when it belongs to a licensed feature.
- **Community can connect to Invardia by choice** - The installer asks whether to connect a Community installation to Invardia for health reports and updates on request. Without a yes, it sends nothing that identifies your tenant or installation.

### Fixes

- **Health report shows the database upkeep is current** - The health report now shows that the database upkeep that keeps pages fast is current, with the time it last ran.
- **Long steps no longer look stalled** - A long step's progress is no longer lost when the clocks of two services differ by a few seconds.
- **Presentation files always save on Windows** - The management presentation's file name is now always one Windows can save, also when its title has characters such as a colon or a question mark.

## 3.1.9 · 2026-11-12 · Fix-only

Large installations finish their nightly work much sooner, and the logs say what really happened.

### New features

None in this version.

### Fixes

- **Configuration items finish much faster** - On large installations the last part of building the configuration items took many hours. Each part now reads only its own records, so it ends much sooner.
- **Logs mention AI only when AI is used** - The privilege tier log now says which catalog version gave the tiers and no longer suggests an AI request that was not made.
- **Risk Analysis warnings name the real failure** - A warning that every way of reading the data failed now names the one that really failed last, with its error. A count used only for timing no longer raises a warning.

## 3.1.8 · 2026-11-11 · Feature update

You can see how far long steps are, and Microsoft's security fixes reach you the same day.

### New features

- **Long steps show their progress** - Long steps such as comparing vulnerability findings and finishing the configuration items now report how far they are every few minutes. A long night no longer looks stuck to you or to support.
- **Microsoft security fixes reach you the same day** - When Microsoft publishes security fixes for the system SecurityInsight runs on, a release with them is tested and rolled out the same day. If it fails, your installation goes back to what it ran before.

### Fixes

None in this version.

## 3.1.7 · 2026-11-11 · Feature update

Your admins' tiers stay current, and one slow report never holds up a run.

### New features

- **Tiers come from a current daily catalog** - Every installation now downloads the daily classified catalog of roles and permissions, checked before it is used. If a download fails, the last good one is kept.
- **Tier classification never holds up a night** - If the catalog cannot be read or built, the night goes on with the last known classification and says so.
- **Break-glass accounts are always Tier 0** - A break-glass account is always Tier 0, whatever roles it holds right now.
- **Built-in roles follow your classification** - With AI integration on, built-in roles follow your own classification instead of the shipped list.

### Fixes

- **One slow report no longer holds a run** - When Microsoft keeps timing out on one heavy report, its retries now get a time limit of 90 minutes, a setting. Parts not read are reported as unknown, never as resolved, and the run goes on.
- **The data health check always reports** - When its last report is more than a day old and the installation is idle, the data health check now runs on its own.
- **Smaller fixes** - The size jump warning appears only on a real jump in a report's size. An old collection job from before the collection was split is removed after 14 days.

## 3.1.6 · 2026-11-11 · Fix-only

The data health check no longer reports missing data that is not missing.

### New features

None in this version.

### Fixes

- **No more false data loss warnings** - The data health check sometimes reported missing vulnerability data although it was stored. It now still reports a real loss, and when it cannot read everything it says so instead of reporting a loss.

## 3.1.5 · 2026-11-11 · Security

The Pro sign-in page carries Microsoft's November security updates.

### New features

None in this version.

### Fixes

- **Security updates applied to the Pro sign-in** - The Pro sign-in page carries Microsoft's November security updates.

## 3.1.4 · 2026-11-11 · Fix-only

SecurityInsight follows rights given through PIM groups, and device pages open fast.

### New features

None in this version.

### Fixes

- **Rights through PIM groups are followed** - SecurityInsight follows rights given through PIM groups, at any depth. No new permission is needed.
- **Device pages open in seconds** - On a large installation a device page now opens in seconds instead of 20 to 30 seconds.
- **Community sign-in page is up to date** - The Community sign-in page is up to date.

## 3.1.3 · 2026-11-11 · Security

The web app, the jobs and the updater carry Microsoft's November security updates.

### New features

None in this version.

### Fixes

- **Microsoft's November security updates applied** - The web app, the AI assistant, the jobs, the updater and the Community sign-in page carry Microsoft's November security updates.

## 3.1.2 · 2026-11-11 · Feature update

Device searches answer in seconds, you can see long steps moving, and nights run steadier.

### New features

- **Device search answers in seconds** - Searching for a device name, a CVE or an id in the detailed findings view now answers in seconds instead of 40 seconds or more. Searching anywhere in the text is still there.
- **Long steps show that they are moving** - Large reports, the data sync and the building of configuration items now report how far they are, for example batch 161 of 266. You and support see that a long night is moving.

### Fixes

- **Brief network failures no longer slow nights** - When a database connection failed for a moment, part of preparing the views was given up and the night ran slower. SecurityInsight now tries again a few times first.
- **Kept open is no longer counted as held** - Findings kept open in your ticketing system until enough complete runs confirm they are gone are now counted on their own. What your ticketing system receives is unchanged.

## 3.1.1 · 2026-11-11 · Fix-only

Cleaning up older data no longer slows your database.

### New features

None in this version.

### Fixes

- **Clean-up gives way to your database earlier** - The clean-up of older collections now pauses when the database reaches 70% load and goes on only below 50%. It still finishes before the next run.

## 3.1.0 · 2026-11-10 · Feature update

SecurityInsight 3.1 runs on a supported platform with data you can trust.

### New features

- **A supported, up-to-date platform** - Since 3.0.85, SecurityInsight runs on Microsoft's long-term supported platform, on Microsoft images that are kept up to date with security fixes.
- **The Invardia support link** - The part that sends health and run results to Invardia support is now called Invardia support link everywhere. One failed report never mails you; the Jobs page turns amber only after three in a row.
- **Every warning explained on invardia.com** - Each warning SecurityInsight shows has its own page on invardia.com: what it means and who acts.
- **One list of who gets which mail** - Configuration > Reports and alerts shows one row per person with a tick per report and alert. Get Started has a new step, Who gets the reports, with your current recipients filled in.
- **Smaller improvements** - The data sync never waits in silence, and overdue findings are counted everywhere. Also included: correlation decisions, deleted users, ServiceNow hand-off and management presentations.

### Fixes

- **Stuck steps open a support case** - A step that runs far past its usual time without progress opens a support case at once.
- **Smaller fixes** - A safety check that held nothing back no longer raises a warning. A source is reported as behind only when its schedule says it should have been read.

## 3.0.88 · 2026-11-10 · Fix-only

Old data is removed steadily without slowing the web app.

### New features

None in this version.

### Fixes

- **Old data is removed without slowing you** - Old data is now removed almost continuously while nothing else runs, as fast as the database allows and slower when it is busy. The web app stays responsive.
- **A growing backlog is never unseen** - When the removal would not finish before the next run, it speeds up. If it still cannot keep up, it says so and support is told.
- **The data sync always goes first** - While the data sync or sending data out runs, nothing is removed.

## 3.0.87 · 2026-11-10 · Fix-only

The data sync never waits for hours in silence, and stuck steps reach support the same day.

### New features

None in this version.

### Fixes

- **The data sync never waits in silence** - The data sync now says about once a minute what each part waits on. A part stuck for 15 minutes is done again; if it is stuck twice, the step says so and the run goes on.
- **Stuck steps open a support case** - A step that runs far past its usual time without progress now opens a support case, so support acts on it the same day.
- **Removing old data waits for the sync** - While the data sync runs, removing old data waits. It goes on in small portions whenever the sync is not running, so even millions of old rows keep going down.

## 3.0.86 · 2026-11-10 · Fix-only

You now see how many findings are past their due date at every installation.

### New features

None in this version.

### Fixes

- **Overdue findings are counted everywhere** - The executive overview's Findings past their due date now works at every installation. A finding is due at its first-seen date plus the accepted time to fix for its asset type, 30 days by default for a patch.

## 3.0.85 · 2026-11-10 · Security

SecurityInsight moves to Microsoft's supported platform, which keeps receiving security updates; it works as before.

### New features

None in this version.

### Fixes

- **Moved to a supported Microsoft platform** - SecurityInsight now runs on Microsoft's long-term supported releases, which keep receiving security updates.
- **Security updates applied** - Every part of SecurityInsight moves to a newer patched base.

## 3.0.84 · 2026-11-10 · Security

Security updates are applied to every part of SecurityInsight; your number and time formats work as before.

### New features

None in this version.

### Fixes

- **Security updates applied** - The web app and the AI assistant now run on a smaller, patched base. Every other part moves to its latest patched version.

## 3.0.83 · 2026-11-10 · Fix-only

Old identities are cleaned up completely, without false warnings.

### New features

None in this version.

### Fixes

- **Old identities are removed** - When SecurityInsight moves to its standard identities, the old identity is removed.
- **No false warning about support access** - Support access checks show the access you agreed to, without false warnings.

## 3.0.82 · 2026-11-10 · Fix-only

Older installations finish moving to the current setup, and support access shows correctly.

### New features

None in this version.

### Fixes

- **Old collection jobs are removed** - An update now removes the old single collection jobs left after the collection was split, once the new jobs have run.
- **Support access is shown correctly** - An older installation now records which Invardia support app it trusts, so its support access shows correctly. Nothing about the app's access changes.
- **The web app keeps its name and address** - The update no longer reports the web app's name as something to move.

## 3.0.81 · 2026-11-10 · Fix-only

Large installations finish their runs reliably and are ready for the next one.

### New features

None in this version.

### Fixes

- **Large runs finish instead of being stopped** - At the end of a run on a large installation, the pages now catch up in steps that report progress, so they always reach the new data.
- **Waiting updates install right after a run** - An update that waits for a run is now installed right after the run ends, before any other run starts.
- **The next run is no longer held back** - A run that ended while its runner was stopped is now closed at once.

## 3.0.80 · 2026-11-09 · Fix-only

Deleted users disappear, your correlation decisions apply everywhere, and reports are never quietly incomplete.

### New features

None in this version.

### Fixes

- **Deleted users are no longer shown active** - Users that Entra ID lists as deleted are retired at once, and their findings close as asset deleted, never as fixed. Expect a one-time retirement of such users after this update.
- **Your correlation decisions apply to assets** - Your merge and split decisions now apply to the assets themselves. Findings that move with a split asset never read as fixed.
- **Reports are never quietly incomplete** - A report that could not read all the data it needs now ends as not complete and keeps its last complete result, instead of finishing with empty columns.
- **Large reports keep going while progressing** - A large report that does not fit in one answer keeps going while it makes progress, and says plainly whether the service was briefly unavailable or the report is too large.
- **Smaller fixes** - Users synchronised from Active Directory are no longer counted twice, so the users count can fall. A failed run during an identity move is no longer blamed on the new identity.

## 3.0.79 · 2026-11-09 · Fix-only

A rebuilt server no longer shows old vulnerabilities from its replaced device record.

### New features

None in this version.

### Fixes

- **Replaced device records no longer count** - When Defender keeps an older record of a rebuilt server beside the new one, the old record's vulnerabilities no longer count. An update missing only on the old record no longer shows.
- **These findings never read as fixed** - Such findings close as report changed, with a plain reason, so your ticketing system never records a fix that was not confirmed.

## 3.0.78 · 2026-11-09 · Fix-only

A template change no longer holds up a whole update.

### New features

None in this version.

### Fixes

- **Code updates go ahead despite template changes** - When a release changes templates you use, the code update now goes ahead. Only the template change waits for an administrator to accept it on the Template releases page.
- **A failed database step retries itself** - If the database setup fails during an update, the update is still held, but the failure is reported and the next update tries again. Nobody has to act.
- **Updates behave the same everywhere** - Updates behave the same whatever protection level your installation's guards have.

## 3.0.77 · 2026-11-09 · Fix-only

Setup status is correct, and identity changes finish reliably.

### New features

None in this version.

### Fixes

- **Setup status shows the web app correctly** - Setup status no longer reports the web app as unfinished while its earlier address is back and the recent one only forwards visitors.
- **Identity moves finish reliably** - Moving SecurityInsight's identities to their standard names no longer stops while waiting for support access it opened itself.

## 3.0.76 · 2026-11-09 · Fix-only

Your web app keeps its familiar address, and old bookmarks work again.

### New features

None in this version.

### Fixes

- **The web app keeps its address** - Every installation keeps its web app name and address. If it recently got a new address, it gets its earlier one back with the same settings and sign-in, checked before use.
- **Bookmarks work again at once** - The recent address keeps working for a few days and sends visitors to the earlier address. Installations that never changed address are not touched.
- **Support tools report their changes correctly** - A support tool now reports its changes correctly once they are made.

## 3.0.75 · 2026-11-08 · Fix-only

Support tools say what they do, and change nothing when they cannot go ahead.

### New features

None in this version.

### Fixes

- **Support tools say what they do** - Support tools say each step as they go. If a tool cannot go ahead, nothing is changed and the tool says why.

## 3.0.74 · 2026-11-08 · Fix-only

Your installation reports its support access as it is set.

### New features

None in this version.

### Fixes

- **Support access is reported as set** - Your installation reports its support access as it is set.

## 3.0.73 · 2026-11-08 · Feature update

Tenants with very many unmanaged on-premises accounts can now leave them out.

### New features

- **Leave out never-synced on-premises accounts** - A new setting, off by default, leaves out on-premises Active Directory accounts that never sync to Entra ID unless they are privileged. Their findings close as retired, never as fixed.

### Fixes

None in this version.

## 3.0.72 · 2026-11-08 · Fix-only

Reports that kept timing out now complete.

### New features

None in this version.

### Fixes

- **Timed-out reports complete in smaller parts** - A report part that kept timing out is now asked again in smaller parts in the same run, so nothing is lost. The next run starts with smaller parts.
- **Long-incomplete reports are named** - A report that has not been complete for several runs in a row now says so, with the date it started.

## 3.0.71 · 2026-11-08 · Security

Deleted secrets and keys can be recovered, and urgent fixes reach you within minutes.

### New features

None in this version.

### Fixes

- **Deleted secrets can be recovered** - Deleted secrets and keys can be recovered during their retention period.
- **Security pack lists the updater's rights** - The security pack lists the updater's rights.
- **Urgent fixes arrive within minutes** - A fix marked urgent is now installed within minutes instead of at the next daily update. Other releases still wait for your installation's own update time.
- **Installation name is kept** - Your installation keeps its name on the vendor portal, and a failed read never clears it.

## 3.0.70 · 2026-11-08 · Security

Support requests go through your installation's own queue, and private-network installs check their network first.

### New features

None in this version.

### Fixes

- **Support requests arrive on your own queue** - Support requests arrive on your installation's own queue.
- **Private-network installs check the network first** - Before it creates anything, a private-network install checks everything it needs and lists everything missing at once, with what to create. Nothing is created until it is there.

## 3.0.69 · 2026-11-08 · Security

Invardia support reaches your data during a support case you agree to.

### New features

None in this version.

### Fixes

- **Support access follows your consent** - Invardia support reaches your data during a support case you agree to, at the level you chose; access ends when the case closes.

## 3.0.68 · 2026-11-08 · Fix-only

You no longer get a false warning about your daily runs.

### New features

None in this version.

### Fixes

- **No false warning about pipeline runs** - The daily check no longer warns that your normal runs ran outside the pipeline. A job that really started outside the pipeline is still reported.

## 3.0.67 · 2026-11-08 · Fix-only

Moving the web app to its new address now needs only one sign-in.

### New features

None in this version.

### Fixes

- **Sign in once after the web app moves** - The old address now sends every page to the new one before anyone signs in, so you sign in once. Your bookmarks keep working.
- **The identity switch now completes** - Every part of the web app uses its new identity after the switch and on every later update.

## 3.0.66 · 2026-11-07 · Fix-only

Updates no longer fail by mistake on a change that was in fact made.

### New features

None in this version.

### Fixes

- **Updates no longer fail a correct sign-in check** - Microsoft Entra can briefly report an old value after a change, so the update's check failed although the change was made. The update now checks again for about half a minute.

## 3.0.65 · 2026-11-07 · Fix-only

The identities SecurityInsight runs as move safely to standard, consistent names.

### New features

None in this version.

### Fixes

- **Identities move to their standard names** - Once switched on, older installations move to the standard identity names one role at a time. Each new identity gets every right and is proven before the old one is removed.
- **Updates report each identity's name** - Every update now tells you, per role, whether the identity carries its standard name.
- **Database administrators group gets its standard name** - The database administrators group is renamed in place, with the same members. New installations create it under that name.

## 3.0.64 · 2026-11-07 · Fix-only

Updates, support work and daily runs no longer get in each other's way.

### New features

None in this version.

### Fixes

- **Updates are no longer held by support work** - A support step no longer starts the database setup during an update, and an update now waits only for its own setup. A busy database is retried.
- **Runs are not cut short by updates** - Right before an update starts, it checks again whether a run has begun and warns when the next run is minutes away. An update started by hand waits for a run that just started.
- **Smaller fixes** - A run retries a short network error while reading its settings. The data fresh start retries a temporary refusal and is much faster.

## 3.0.63 · 2026-11-07 · Fix-only

Your web app moves to its standard name without breaking bookmarks.

### New features

None in this version.

### Fixes

- **Web app moves to its standard name** - A new web app is created beside the old one and checked. The old address then forwards every page, and is removed only after someone signs in on the new one.
- **Custom addresses are never moved silently** - An installation with a custom domain or a custom public address stops before the move and tells you so.
- **Sign-in stays set up across updates** - SecurityInsight keeps its own sign-in set up across updates.
- **Smaller fixes** - Database setup now records which Invardia Support app your installation trusts.

## 3.0.62 · 2026-11-07 · Fix-only

The web app keeps its database access during an identity change.

### New features

None in this version.

### Fixes

- **Web app keeps its database access** - The web app keeps its database access during an identity change, also when it has more than one identity.

## 3.0.61 · 2026-11-07 · Fix-only

Your merge and split decisions on correlation suspects are saved again.

### New features

None in this version.

### Fixes

- **Merge and split decisions save again** - Saving a merge or split decision on the correlation suspects page failed. The update now gives the web app the right it needs, so decisions save and can be undone.

## 3.0.60 · 2026-11-07 · Fix-only

A requested fresh start of your data no longer takes hours on large tables.

### New features

None in this version.

### Fixes

- **Data fresh start runs quickly again** - A fresh start of your data could fall back to deleting rows slowly, taking hours on a large table. It is now much faster, and a rerun continues where it stopped.

## 3.0.59 · 2026-11-07 · Feature update

Settings you never changed now always work with their defaults.

### New features

- **Fresh start of your data on request** - On your request, your data can start fresh, keeping settings, templates, audit trail, users and roles. A plan is shown first and the result is checked.

### Fixes

- **Unchanged settings now use their defaults** - A few settings you never stored had no value when a job started. They now always take their shipped default.
- **Unwanted accounts and groups are now left out** - Two identity settings on by default are now applied: on the first run, inactive never-synced Active Directory accounts and groups Entra ID no longer has are retired. To keep them, turn the setting off.
- **Smaller fixes** - An output's progress line now says rows to read when it estimates from the data, and privilege tiers are worked out again once. Updates name the script to run for web app sign-in assignment.

## 3.0.58 · 2026-11-07 · Fix-only

The data sync at large installations finishes in normal time again.

### New features

None in this version.

### Fixes

- **Large data syncs no longer take days** - At a large installation, one step of the data sync could take a day or more. It now reads only what it needs and is much faster.

## 3.0.57 · 2026-11-06 · Fix-only

A stuck job no longer holds back your daily collection.

### New features

None in this version.

### Fixes

- **Stuck jobs no longer block the daily run** - SecurityInsight now stops its own jobs that show no sign of life for 15 to 30 minutes, so the waiting run starts. A job that is still working is never stopped.
- **Building the CI list survives a hiccup** - A temporary database answer while building the CI list is now retried, so a long build no longer has to start again.
- **No more warning about support requests** - The update again makes sure support requests can be delivered. The warning shown on every run for the last few days is gone.

## 3.0.56 · 2026-11-06 · Fix-only

One moved asset no longer holds back closing your vulnerabilities.

### New features

None in this version.

### Fixes

- **One unclear finding no longer blocks every close** - When an asset moved to another CI, one unclear finding stopped every close in the run. Now only the CIs concerned are held, and the run's warning names them.
- **Smaller fixes** - Database setup can now run during a pipeline run. Moving to new identity names now checks the moved rights completely.

## 3.0.55 · 2026-11-06 · Fix-only

Database setup now completes on its first try.

### New features

None in this version.

### Fixes

- **Database setup finishes in one run** - On an installation with the optional Support app, the database setup step used to need a second run. It now finishes and checks everything the first time.

## 3.0.54 · 2026-11-06 · Fix-only

Waiting updates start right after a run, and pages are fast as soon as new results show.

### New features

None in this version.

### Fixes

- **Waiting updates start right after a run** - An update that waits for a long run now always starts right after the run ends, never the next night.
- **Pages are fast when new results show** - The database upkeep that keeps pages fast runs once after the run's results are published, so pages are fast at once.
- **Short hiccups no longer stop setup or updates** - Database upkeep, database setup and updates now retry a short network or sign-in hiccup instead of stopping. The update also finds the Support app by itself.

## 3.0.53 · 2026-11-05 · Fix-only

Database setup keeps working on its own, and a missing Defender licence no longer fails reports.

### New features

None in this version.

### Fixes

- **Database setup keeps its own access** - Database setup keeps working after every update without anyone granting rights again.
- **Admin group changes are proven or rolled back** - Moving the database admin to another group is proven by a real sign-in, and rolled back automatically when that fails.
- **Reports show not applicable without Defender licence** - A report whose Defender data is not in your tenant, for example without Defender vulnerability management, shows as not applicable again. A real report problem is still shown as failed.
- **Smaller fixes** - Updates keep pages fast in the background, and setup lines reach your log workspace.

## 3.0.52 · 2026-11-05 · Fix-only

Pages stay fast after every run.

### New features

None in this version.

### Fixes

- **Pages stay fast after every run** - At the end of every run, SecurityInsight prepares the database for fast pages, so pages never wait while you look. If this cannot run, the run still completes.
- **Device close-loop list opens quickly** - A device's close-loop list now reads only that device's findings. It could take more than a minute before.
- **New installations keep pages from waiting** - New installations keep the database prepared in the background, so reading a page never waits.

## 3.0.51 · 2026-11-05 · Fix-only

Pages answer much faster, and an update no longer makes the web app hang.

### New features

None in this version.

### Fixes

- **Views answer in a fraction of the time** - Navigation, the device page, a CI's findings and history, the Summary view and the audit trail now answer much faster, also during a run. Every view shows exactly the same rows.
- **The web app no longer hangs during updates** - While an update changes the database, the web app shows a short notice that SecurityInsight is being updated and comes back by itself.
- **Faster runs at large installations** - Unchanged findings are no longer rewritten on every run, and one step at large installations is many times faster. What SecurityInsight sends to your other systems is unchanged.
- **Updates no longer block pages at sign-in** - An update no longer re-creates unchanged parts of the database, so pages read at sign-in are not blocked while it runs.
- **Smaller fixes** - Slow page reads are logged, and the device page names each finding from the published run. Run records Invardia could not receive are kept and sent later.

## 3.0.50 · 2026-11-05 · Fix-only

A private installation can always build its updates.

### New features

None in this version.

### Fixes

- **Private installs can always build updates** - An update keeps the machines that prepare a private installation's updates in place, so every update can install. Between updates they scale down to none.

## 3.0.49 · 2026-11-05 · Feature update

Your CI list stays stable and complete, and you now see every user's sign-in methods.

### New features

- **See every user's sign-in methods** - SecurityInsight now reads each user's sign-in methods in full, including the device a key lives on. A setting chooses every user, privileged users only or none.
- **Assumptions page shows collection scope in force** - The Assumptions page shows every collection-scope setting with the value in force.
- **Close-loop table names every finding** - An asset's close-loop table names each finding with its title and kind, such as CVE, recommendation or certificate, and counts every item.

### Fixes

- **One stable CI per machine** - A merged CI's id is never reused, and a CI that returned after a merge is retired into the right CI with its findings. Nothing is deleted.
- **ServiceNow learns every CI state and reason** - Every inactive CI is sent to ServiceNow with its state and a plain reason, such as merged or not seen since a date. No CI is ever dropped.
- **Gone machines retire after their grace period** - A device or Azure resource that only Microsoft's security data still lists now retires after its grace period. Dormant accounts stay, as a risk to report.
- **Private installs cost nothing between updates** - The machines that prepare a private installation's updates run only while they work and scale to none afterwards. Upkeep of large tables pauses whenever an update waits.
- **Smaller fixes** - An Azure VM's SQL Server is linked under the VM's CI, and nameless Defender devices get a generated name. Every CI is rebuilt once after this update.

## 3.0.48 · 2026-11-05 · Fix-only

Updates never stop a running pipeline, and identity reads are faster at large tenants.

### New features

None in this version.

### Fixes

- **Updates never cancel a running pipeline** - An update now waits for a run to end and installs between two runs. An update never stops a running pipeline.
- **Private installs get more time to build** - An update now waits up to 90 minutes for its build, since a private installation builds inside its own network.
- **Faster identity reads at large tenants** - With the setting to skip inactive never-synced on-premises accounts on, those accounts are no longer read at all. The log says how many were skipped.

## 3.0.47 · 2026-11-05 · Fix-only

A new installation's first Risk Analysis no longer waits for hours.

### New features

None in this version.

### Fixes

- **First collection starts Risk Analysis at once** - On a new installation's first collection, Risk Analysis used to wait hours for the asset build at a large tenant. It now starts at once.
- **Support status shows where access is set up** - The support status shows which databases have support access set up.

## 3.0.46 · 2026-11-05 · Security

Support sessions are short, and the Community installer verifies every download.

### New features

- **Community installer verifies every download** - The Community installer verifies every download before it installs it.

### Fixes

- **Support sessions last at most 8 hours** - A support session lasts at most 8 hours.
- **Smaller fixes** - Database setup finds each part's identity during a name move.

## 3.0.45 · 2026-11-05 · Feature update

SecurityInsight now sets up its own database access, so nobody needs database admin rights for updates.

**Action needed:** For an existing installation, add the database setup job's identity to your SQL admin group once.

### New features

- **SecurityInsight sets up its own database access** - A built-in setup job now creates and checks the database access the product needs. Every update runs it first; if it fails, your installed version keeps running.

### Fixes

- **Support level applies in every database** - The support level you set in the Invardia portal applies to all your SecurityInsight data.
- **Smaller fixes** - Asset tagging gets its database access from the update, and two manual database scripts are no longer needed for Pro.

## 3.0.44 · 2026-11-04 · Fix-only

Accounts and groups that no longer matter are left out of your assets by default.

### New features

None in this version.

### Fixes

- **Inactive identities are left out by default** - Never-synced Active Directory accounts that are disabled and not privileged, and groups Entra ID no longer has, are no longer assets by default. A value you chose is kept; turn a setting off to record them again.
- **Left-out items retire, never count as fixed** - Their existing assets retire with a reason naming the setting, and their findings close as asset retired, never as fixed. The Data health page counts what was left out.
- **Same install lines everywhere** - The two install lines are now the same in the README, release notes, release page, documentation and the installer's help.

## 3.0.43 · 2026-11-04 · Feature update

Reports complete on large tenants, and you set the support level in the Invardia portal.

### New features

- **Set the support level in Invardia portal** - The Invardia Support app's access level (none, troubleshoot or setup) now follows what you set in the Invardia customer portal.

### Fixes

- **Reports complete on large tenants** - Attack path and administrator sign-in reports could end incomplete on a large tenant. SecurityInsight now waits, asks again and works in parts, so the reports complete with the same rows.
- **Device reports work on Defender for Business** - The missing CVE, recommendation and end-of-support software reports now return rows when Defender has no device inventory, for example Defender for Business. Open findings keep their history.
- **Heavy jobs get more computing power** - Collections, correlation, Risk Analysis, the data sync and vulnerabilities now get more computing power and memory. No job is ever made smaller.
- **A stopped run is partial, not failed** - A collection stopped by an update, by support or by a person is now reported as partial, with that reason. Only a run that itself failed is reported as failed.
- **Smaller fixes** - Stopping a run and updating is one checked step. The one-time cut-off now reads its own setting back correctly.

## 3.0.42 · 2026-11-04 · Fix-only

Every change of this version reaches you with 3.0.43.

### New features

None in this version.

### Fixes

- **Included in 3.0.43** - This version was not released to every installation. Every change in it is part of 3.0.43.

## 3.0.41 · 2026-11-04 · Feature update

Large installations can get a clean fresh start, and a private installation gets a private AI account.

### New features

- **One-time fresh start for large installations** - On your request, a one-time cut-off can be set so older records no longer build CIs. CIs built only from them retire with that reason, and nothing is deleted.

### Fixes

- **Private AI account on private installs** - On a private installation the optional AI account is private, or AI stays off and setup says why.

## 3.0.40 · 2026-11-04 · Fix-only

Inherited Azure tags now appear in every collection mode, and installs run more smoothly.

### New features

None in this version.

### Fixes

- **Inherited Azure tags in every collection mode** - Azure records collected in parts, as larger installations do, now carry the tags they inherit from resource group, subscription and management groups. The log says how many were read.
- **New installs no longer wait for sign-in keys** - The install now creates the web app's sign-in key in your secure key store and grants its use itself. If you may not assign roles, the grant is listed as a task.

## 3.0.39 · 2026-11-04 · Fix-only

Collections no longer run a second time each day outside your pipeline.

### New features

None in this version.

### Fixes

- **No extra daily collection outside the pipeline** - Endpoint, Identity and Azure collections no longer run a second time a day on their own timer. Installations that run jobs on their own schedules keep their timers.
- **Jobs page shows collections as pipeline steps** - The Jobs page shows these three collections as pipeline steps again, and saving the pipeline keeps them.
- **Collections outside the pipeline are reported** - A daily check now warns about any collection that did not run inside the pipeline and was not started by a person.

## 3.0.38 · 2026-11-04 · Fix-only

A private installation's web app now answers from your own network.

**Action needed:** On a network you provide, have your network team take the network step the install names.

### New features

None in this version.

### Fixes

- **Private web app answers from your network** - On a network SecurityInsight creates, the web app of a private installation now answers people on your own network.
- **Two editions never share a resource group** - When the resource group already holds the other SecurityInsight edition, the install stops before creating anything and asks you for another name.

## 3.0.37 · 2026-11-04 · Fix-only

New installations get short, consistent resource names.

### New features

None in this version.

### Fixes

- **New installs get short, standard names** - A new installation names its resources the short, standard way and keeps those names on every rerun. Names you choose still win, and existing installations are never renamed.

## 3.0.36 · 2026-11-04 · Fix-only

A private installation now finishes its install cleanly.

### New features

None in this version.

### Fixes

- **Private installs pass their final check** - The final health check now checks a private installation's database the private way.
- **New groups are ready before members join** - Adding a member to a group SecurityInsight just created now waits up to five minutes for Microsoft Entra, instead of stopping.
- **Support access step ends cleanly** - On a fresh installation, the support access step now ends without an error.

## 3.0.35 · 2026-11-04 · Fix-only

Azure records show their inherited tags, and installs no longer stop over outside permissions.

**Action needed:** Have someone with the rights complete the permission tasks the installer lists.

### New features

None in this version.

### Fixes

- **Azure records show inherited tags** - Every Azure record now carries the tags it inherits from its resource group, subscription and management groups, with where each comes from. The nearest level wins.
- **Outside permissions no longer stop installs** - When the installer may not set a permission outside SecurityInsight's resource group, the grant is listed as a task and the install continues.

## 3.0.34 · 2026-11-04 · Fix-only

New public installations no longer stop at the secure key store step.

### New features

None in this version.

### Fixes

- **New public installs get past the key store** - A new public installation no longer stops partway. Private installations are unchanged.

## 3.0.33 · 2026-11-04 · Fix-only

Private installations can now build their updates inside your network.

**Action needed:** Have your network team take the step the install names.

### New features

None in this version.

### Fixes

- **Private installs can prepare their updates** - On a private installation, the network SecurityInsight creates now lets the machines that prepare updates start. Nothing becomes reachable from outside.
- **Clear step when your network needs a change** - On a network you provide that the update machines cannot start in, the install stops and names the one step your network team takes.
- **Updates repair stalled update machines** - An update repairs a private installation whose update machines do not run.

## 3.0.32 · 2026-11-04 · Fix-only

A private installation no longer stops while Azure prepares its build machines.

### New features

None in this version.

### Fixes

- **Private installs wait for their update machines** - A private installation now waits up to 30 minutes while Azure creates the machines that prepare its updates, with progress every minute. A failed one is made again on the next run.

## 3.0.31 · 2026-11-04 · Fix-only

A private installation builds and keeps its updates inside your network.

### New features

None in this version.

### Fixes

- **Private installs build updates inside your network** - On a private installation, updates are built and kept inside your network. Your network team gets the details it needs.
- **Smaller fixes** - Resuming an install downloads the right release, and the install shows the version it installs.

## 3.0.30 · 2026-11-04 · Feature update

Your database stays lean, duplicate assets disappear, and you can open SecurityInsight straight from Invardia.

### New features

- **Open SecurityInsight from the Invardia portal** - The Invardia overview and every support mail about your install now carry an "Open SecurityInsight" link.
- **Documentation for your version in the portal** - The Invardia portal and invardia.com now show the install options, the reference and the release notes for the version you run.

### Fixes

- **Database no longer grows between busy runs** - Old finding data is now removed while a run is going, paced by the database's load, so installs with back-to-back runs clean up too.
- **Duplicate asset records are merged at once** - An asset stored twice is now merged at once, also in what goes to ServiceNow. A new install's first run no longer creates such copies.
- **Brief database interruptions no longer fail a run** - When the database is briefly unavailable, the work is sent again where that is safe, instead of failing the step.
- **Pro install waits for its licence** - A Pro install without its licence now waits for it instead of stopping with an error. The licence then arrives through the update.
- **Smaller fixes** - A full database is reported as its own cause, failed steps name their error, the web app's key check no longer reports a problem that is not there, and setup status reaches Invardia.

## 3.0.29 · 2026-11-03 · Fix-only

Installs succeed more reliably.

### New features

None in this version.

### Fixes

- **Your secure key store is set up correctly** - Your secure key store gets its network settings from the start, whether the install creates, restores or finds it.
- **Re-installing restores a deleted key store** - Installing again over a deleted SecurityInsight secure key store now takes it back, with its keys and secrets, instead of stopping.
- **Region check respects your Azure policies** - The region check now uses the same settings as the real resources, so a policy that requires those settings no longer refuses it.
- **Smaller fixes** - The support scripts now come as one complete set, each file checked, with documentation of the same version.

## 3.0.28 · 2026-11-03 · Fix-only

The install tells you at once when your region cannot take new resources, before anything is created.

### New features

None in this version.

### Fixes

- **Install checks your region first** - Before anything is created, the install checks that your region takes new resources in this subscription. If not, it stops at once and names nearby regions that do.
- **Smaller fixes** - A private install reads its network settings reliably.

## 3.0.27 · 2026-11-03 · Feature update

Installing the Community edition is now quick and simple.

### New features

- **Community edition installs in two lines** - You download the installer from the latest release and run it with your tenant and subscription. No code copy and no config file are needed.
- **Smaller improvements** - The README, the script help and the docs now show the same two lines, with only the settings an install uses.

### Fixes

None in this version.

## 3.0.26 · 2026-11-03 · Feature update

Pro installs now come straight from Invardia, signed and checked, and several install problems are fixed.

### New features

- **Pro installs come from Invardia** - The Pro install line from invardia.com now gets the signed and checked Pro package from Invardia, and you sign in once. The Community edition still installs from GitHub.

### Fixes

- **Install fixes from recent versions** - A Pro install without a licence starts, a new subscription's quota no longer stops it, a second run in one window signs in again, and the installer gets data access.

## 3.0.25 · 2026-11-03 · Fix-only

The person who installs SecurityInsight can now reach its data straight away.

### New features

None in this version.

### Fixes

- **The installer gets access to the data** - The install now gives the person installing access to SecurityInsight's data.

## 3.0.24 · 2026-11-03 · Fix-only

Running the install a second time no longer stops at sign-in.

### New features

None in this version.

### Fixes

- **A second install run signs you in** - Running the install again in the same window now signs you in again instead of stopping with "You are not signed in".

## 3.0.23 · 2026-11-03 · Fix-only

The install now completes in a fresh subscription.

### New features

None in this version.

### Fixes

- **Install goes on in a new subscription** - In a subscription never used for SecurityInsight's kind of jobs, the install no longer stops at the capacity check. Capacity is checked when the environment is created.
- **A second install run signs you in** - Running the install again in the same window signs you in again instead of stopping at the subscription check.

## 3.0.22 · 2026-11-03 · Fix-only

A Pro install from invardia.com now starts even before you have a licence.

### New features

None in this version.

### Fixes

- **Pro install starts without a licence** - The Pro install no longer stops at the tenant and subscription check. It deploys the whole environment and waits for your licence, as intended.

## 3.0.21 · 2026-11-03 · Feature update

You can install SecurityInsight unattended with one command, and resume it if it stops.

### New features

- **Install with one command** - Every setting of the guided install is now an option on one command, so the install runs unattended and reports each step. Only the tenant and subscription are required.
- **Install before you have a licence** - The install deploys the whole environment without a licence and runs nothing paid until one is assigned. It then takes its licence by itself.
- **Continue a stopped install** - If an install stops, you continue it with the same command and the Resume option.

### Fixes

None in this version.

## 3.0.20 · 2026-11-03 · Feature update

Your Azure resources and ServiceNow records now show owner and purpose tags inherited from higher levels.

### New features

- **Resources inherit tags from their parents** - An Azure resource now also shows the tags of its resource group and subscription, marked with their origin. Its own tag wins, and untagged resources now get owner, application and purpose.
- **Tags sent to ServiceNow** - The ServiceNow hand-off offers three new columns: all tags, own tags and inherited tags. ServiceNow ignores them until your ServiceNow team adds them.
- **Tags in rules, reports and connectors** - Every tag of an asset, its own first and then the inherited ones, is now available as one field for rules, reports and connectors.
- **An easier CI page** - Tags show their values, field names stay on one line, you can resize small table columns, and the field sources table shows each value.

### Fixes

None in this version.

## 3.0.19 · 2026-11-03 · Fix-only

Your database stays lean at busy installs, and jobs keep enough power for your tenant.

### New features

None in this version.

### Fixes

- **Old collections cleaned up during runs** - At installs with back-to-back runs, older data is now removed while a run is going. It waits when the database is busy and never slows a run or a ServiceNow send.
- **Every update checks job sizes** - Each update now checks the processing power and memory of the jobs and the web app, and raises any that is too small for your tenant.

## 3.0.18 · 2026-11-02 · Feature update

Your asset list is cleaner, with fewer duplicate machines, and you choose what goes to ServiceNow.

### New features

- **Choose which assets go to ServiceNow** - You can limit the items sent to ServiceNow by asset type and operating system, for example keeping mobile phones out while Windows, Linux and Azure resources go.
- **Decide on probable duplicate devices** - A data-quality check lists devices that are probably the same machine. You decide "same machine" or "not the same", and the next build uses your decision.
- **Retire proven-deleted assets at once** - An asset proven deleted can now be retired at once instead of after 30 days, with its open findings closed. One switch per source, all off by default.
- **Leave out stale accounts and groups** - You can choose to leave out disabled Active Directory accounts that never synced, and groups no longer in Entra ID. Both are off by default; privileged accounts are always kept.
- **Smaller improvements** - The CI list's lifecycle filter is in both filter panels.

### Fixes

- **One CI per domain-joined computer** - A computer's Active Directory account is no longer a second device beside the machine itself. It is linked to the device it belongs to.
- **Placeholder device names no longer join devices** - A device with a placeholder name takes its name from another source or a clear generated name. A placeholder name never joins two devices.
- **Smaller fixes** - The ServiceNow check counts items without a database error, page texts name menu paths the same way, and the updater keeps its timers in step.

## 3.0.17 · 2026-11-01 · Feature update

Sending to ServiceNow is much faster, and you can follow its progress.

### New features

- **Follow ServiceNow send progress** - While it sends, you see the phase, rows sent of rows planned, rows held and time left. A send without progress for 10 minutes says so.

### Fixes

- **Vulnerable items built three times faster** - Vulnerable items for ServiceNow are now built about three times faster. On large installs, the pass over closed findings takes hours less, with the same rows sent.
- **Refused sends are reported at once** - When ServiceNow refuses or holds a send, SecurityInsight says so at once and stops. Nothing is counted as sent that was not.
- **Smaller fixes** - The install always identifies itself to Invardia the same way, and shows its hand-off progress in its status.

## 3.0.16 · 2026-11-01 · Fix-only

Vulnerable items reach ServiceNow again, and one oversized value no longer holds back the rest.

### New features

None in this version.

### Fixes

- **Vulnerable items reach your own ServiceNow tables** - Your own ServiceNow tables now receive vulnerable items, whatever their name.
- **One long value no longer blocks everything** - A value too long for its ServiceNow column now holds only its own row. The other rows are sent, and the held rows go once the column is wider.
- **Long identifiers fit ServiceNow** - A long vulnerable item identifier is shortened the way ServiceNow expects, so it fits the column.

## 3.0.15 · 2026-11-01 · Fix-only

Your data reaches ServiceNow sooner, and the monthly review mail is sent again.

### New features

None in this version.

### Fixes

- **ServiceNow receives data sooner** - Sending to ServiceNow and your other systems now starts as soon as the newest findings are stored, without waiting for the rest. A resend takes minutes.
- **Monthly review mail is sent again** - The technical owners' monthly review mail is sent again. It stopped in the two previous versions.
- **Old data removed in the background** - Old collections are removed a little at a time while nothing else runs, with progress in the status. The newest two complete collections are always kept.

## 3.0.14 · 2026-11-01 · Fix-only

Your data reaches ServiceNow again.

### New features

None in this version.

### Fixes

- **ServiceNow receives its rows again** - Configuration items and vulnerable items reach ServiceNow again after the last three versions stopped before sending. The next send delivers everything that is due.

## 3.0.13 · 2026-11-01 · Security

This version strengthens SecurityInsight's security.

### New features

None in this version.

### Fixes

- **Security strengthened** - The web app and the AI assistant carry the security improvements of this release.

## 3.0.12 · 2026-11-01 · Security

This version strengthens SecurityInsight's security.

### New features

- **AI summaries through your own gateway** - AI summaries use your Azure OpenAI service, directly or through an Azure API Management gateway in front of it.

### Fixes

- **Security strengthened** - Everyone signs in once more after the update.
- **Smaller fixes** - Error messages on pages say what you can do.

## 3.0.11 · 2026-11-01 · Fix-only

The ServiceNow hand-off no longer stops with an error, and the detailed risk analysis finishes hours sooner on large installs.

### New features

None in this version.

### Fixes

- **ServiceNow hand-off no longer stops with an error** - Configuration items and vulnerable items no longer stop with a database error. The next send closes the stopped batches and prepares their rows again.
- **Detailed risk analysis is much faster** - The Detailed risk analysis reads its results once instead of twice, with the same numbers. On the largest installs this saves hours.

## 3.0.10 · 2026-10-31 · Feature update

Your run figures are back, and the ServiceNow hand-off is prepared from every run.

### New features

- **Build a presentation from the Executive report** - A wizard builds a PowerPoint presentation from the Executive report. The monthly management pack is attached to the management summary mail.

### Fixes

- **Finding counts are back** - What was new, seen again, reopened and closed shows again in the log, the run record and the mail, so every close is counted.
- **ServiceNow hand-off prepared from every run** - The configuration items for ServiceNow are prepared from every run. The check before each send no longer needs ServiceNow's table list; without it only the column check is left out, with a warning.
- **Clearer ServiceNow messages and setup list** - A refusal says what ServiceNow said. The page for your ServiceNow team lists the user, every role, the table settings and every call SecurityInsight makes.
- **Smaller fixes** - A step whose job stops before it begins is started again once, and the column fill check no longer reports blank columns that are not blank.

## 3.0.9 · 2026-10-29 · Feature update

Large installations run steadily and updates always get through.

### New features

- **Risk Score parts as columns** - The parts of the Risk Score are now columns in the Detailed and Summary findings, shown by default. You can sort and filter by them.
- **Easier filtering and selection in findings** - The findings grids use the same filter panel as the CI list. Shift+click selects a range of rows; Ctrl+click adds one more.
- **See what a running step does** - Operations > Jobs shows job runs started outside the pipeline, and what a running step is doing now, with progress where the step counts it.
- **Install in one line** - The install takes the common answers as options, so the quickest install is one line. The install page and the README show five samples.

### Fixes

- **Updates always get through** - While an update waits, no new run starts, so it installs when the current run ends. After six hours it ends a run from an older version, installs, and the next run starts on the new one.
- **Large installs finish their data sync** - The data sync now works in bounded parts, and a sync that stops part-way is finished by the next. Brief database failures are retried for up to nine minutes.
- **Runs no longer hang on an ended step** - A step whose job ended on its own is now closed, so the run goes on. Cancelling a run now works while it is active.
- **Run reports reach Invardia again** - Collection run reports reach Invardia again, and each lists the steps that succeeded, so a solved problem closes by itself. Very slow steps are named.
- **Smaller fixes** - Asset pages no longer warn of old data during a refresh, a sharp drop in assets from one source no longer sends a mail, and ServiceNow import problems show on the Guards page again.

## 3.0.8 · 2026-10-29 · Fix-only

Your install reports its status to Invardia again.

### New features

None in this version.

### Fixes

- **Status reports reach Invardia again** - Since version 3.0.5 an install stopped sending its status report to Invardia. The status and run reports now go out as before.

## 3.0.6 · 2026-10-29 · Feature update

Filtering findings by category, subcategory and department is now quicker.

### New features

- **Dropdown filters for category and department** - Category, Subcategory and Department are now dropdown filters on the Summary and Detailed findings. You tick one or more values and see the number of findings for each.

### Fixes

- **Easier-to-read filter menus** - In every filter's value menu, each value now sits next to its tick box.

## 3.0.5 · 2026-10-29 · Fix-only

Run now and every other start from the web app keep working.

### New features

None in this version.

### Fixes

- **Job starts keep working** - After a change at Microsoft, every start from the web app, such as Run now, keeps working. A start that fails never runs later.

## 3.0.1 · 2026-10-28 · Feature update

The Community edition now includes more of SecurityInsight, and its updates are checked before they install.

### New features

- **More features in the Community edition** - Cross-engine correlation and full asset properties are now part of the Community edition. Asset tagging, verification and data health are in both editions.
- **Checked updates for the Community edition** - A Community install updates from the SecurityInsight update channel. Every release is verified before anything is installed.
- **Smaller improvements** - The Community edition shows its own logo in the web app, and version numbers are short.

### Fixes

- **Updates never overlap** - An update never overlaps another one that is still running, and a running update keeps reporting its stage, so it never looks hung.
- **Failed data sync parts are reported** - When part of the data sync fails, for example because the database is full, the run reports it as failed instead of finishing as if all was well.

## 3.0.0 · 2026-10-01 · Feature update

SecurityInsight 3 brings two editions, safe automatic updates, and settings that finally take effect.

### New features

- **Two editions: Community and Pro** - SecurityInsight now comes as a free Community edition and a licensed Pro edition. Pro adds cross-engine correlation, the ServiceNow connector and sending vulnerabilities to ServiceNow or a database, with managed updates.
- **Safe, signed updates** - Updates come through a signed update channel in stages, are checked before use and restore the previous version on failure. Pro installs update and renew their licence from Invardia by themselves.
- **Findings never close when a source goes silent** - When a data source that had data suddenly returns none, the affected reports keep their last complete result. None of their findings is closed or marked as fixed.
- **One daily pipeline: Collect, Correlate, Deliver** - The daily jobs run as one pipeline at 22:00 in your time zone, and nothing is delivered from an incomplete collection. Run now works on the whole pipeline, a stage or a step.
- **Smaller improvements** - The Detailed report is now the default. Also new: Defender for Cloud recommendations and vulnerabilities, a daily trend in Community, managed identity sign-in by default, report-only asset tagging, and visible version numbers.

### Fixes

- **Your settings now override shipped defaults** - Settings in your own configuration now win over the shipped defaults, as documented. This affects about 60 settings.
- **Your asset rules win over the CMDB** - When your own asset rule sets a CMDB name, criticality or data sensitivity, that value now wins over the CMDB record, field by field.
- **Reports see every vulnerability and recommendation** - The vulnerability reports now also read Defender Vulnerability Management directly, and Azure recommendations no longer go missing. Expect these reports to grow.
- **One machine, one tier everywhere** - A machine seen by several sources is one asset with one tier and one name in every report. Large Summary reports also keep every asset.
- **Smaller fixes** - Trend figures now count assets, devices sharing a name are profiled separately, hosted jobs receive all your non-secret settings, Shodan included, and Risk Analysis and asset profiling are more accurate.
