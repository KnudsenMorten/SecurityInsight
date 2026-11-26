# Remediation tasks

*SecurityInsight Pro.* A remediation task is one thing to do on one asset: install an update, upgrade a piece of
software, or change a setting. The findings and CVEs the task resolves are listed on it. SecurityInsight works the
tasks out from every daily run, so you can hand IT operations a list of work instead of a list of findings.

You find them on **Remediations > Tasks per asset**.

## What becomes a task

- **A security update for the operating system**: one task per update on each asset.
- **A software upgrade**: one task per product and installed version on each asset. Two versions of the same product
  on one asset are two tasks.
- **A library bundled inside another program**: one task per application that bundles it, with every path of that
  copy. The fix comes from the vendor of that application.
- **A configuration setting**: one task per setting on each asset. The same goes for an Azure recommendation, an
  attack path and an identity rule.

A finding with no known fix gets no task. A task is never named after the asset itself.

## Tasks per asset and their findings

*Tasks per asset* shows one row per asset and task, with the findings and CVEs it resolves, its highest severity and
risk rating, the asset's owner and the task's state. Open an asset for everything known about it, a task's name for
the task's own page, and a task's findings count for the findings it resolves (the *Task findings* view). For a
bundled library, the findings show the paths of that copy. Both views can be exported.

The task's own page shows what the task is and its state, what to do (the recommended update, the application and its
version, every detected path, the bundled library and its version), the asset it covers, its dates, and the findings
it resolves, each linked to its finding. Its findings can be exported like every view.

A person whose access is limited to some departments sees only the tasks with findings they may see.

## When a task closes

A task stays open while any of its findings is open. It closes with one of these reasons:

| Reason | When |
|---|---|
| Fixed | Every finding of the task is proven gone on complete runs. For a bundled library: the paths of that copy no longer hold the vulnerable version. |
| Exempted | Every finding still there is exempted. When the exemption ends, the task opens again. |
| Asset retired | The asset is retired. |
| Report changed | The report that found it now asks something else. |
| Task changed | The finding is still there, but it now belongs to another task, for example after a version change. |

When SecurityInsight cannot tell, the task is kept as it was: after an incomplete run, for an asset that was not seen,
or when the software evidence of a bundled copy could not be read. A closed task that comes back opens again and counts
as reopened. Closed tasks are kept for 365 days by default, like closed findings.

## Task reports for IT operations

**Remediations > Task reports** groups the same tasks so IT operations can plan the work. Every report can be exported,
and a row opens the assets and tasks behind it.

- **Deploy once, fix many**: one row per task across all your assets: how many assets it is open on and how many of
  them are Tier 0 or Tier 1, the CVEs it removes, the findings it closes, its highest severity and risk rating, and the
  tool that fits (patch tool, software deployment, policy, Azure or manual). A task open on at least the minimum number
  of assets for a fleet-wide deployment (an Admin setting) is marked as a candidate and comes first; then the order is
  the weighted risk the task removes.
- **By product**: one row per product with open tasks, how many assets run it and how many versions are in use.
- **By tool, owner, IT service ...**: the open tasks grouped by one dimension, such as the tool, the owner or
  department, the IT service, the OS and its version, the risk rating or how long the tasks have been open. A task
  counts under every value it has, so rows can overlap.
- **No mass action fits**: the open tasks whose action is open on fewer assets than the minimum, so someone must act on
  each asset.
- **Opened and fixed per week**: per week, the tasks opened, closed as fixed and closed for another reason, and how
  many were open at the week's end.

Every task report, *Tasks per asset* and *Task findings* filter by IT service (from the CMDB link), OS and OS version,
device type, cloud subscription, resource group, location, tool, kind, tier, owner, department and age, and by the
findings' severity, risk rating, security domain, category and subcategory. A task matches when one of its findings
matches, and it is then counted over those findings.

## Tasks everywhere else

- **The management report** has a chapter 6, *Remediation*: the open tasks and the assets they cover, the tasks opened
  and closed as fixed since the last report, the oldest open task, the open work per tool, and the **Top 50 actions**.
  The Top 50 actions are shown in full on the page, in the PDF and in the mail, and on five slides in the presentation
  pack.
- **The asset page and the CI page** show the asset's tasks, open first.
- **A finding's page** lists the task it belongs to.

## To ServiceNow

The tasks and their findings can be sent to ServiceNow as two outputs of their own. See [ServiceNow staging tables
and columns](servicenow-columns).
