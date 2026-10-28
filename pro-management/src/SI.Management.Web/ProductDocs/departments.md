# Departments

Departments own assets and the findings on them. With departments, each team sees its own findings, gets its own
reports, and decides on its own requests.

There are two places in the web app:

| Where | Who | What |
|---|---|---|
| **Configuration > Departments (setup)** | Admins | Create departments, add people and roles, set the rules that place assets, and define remediation flows. |
| **Operations > Departments** | Everyone on a department, and readers | A department's own page: its assets, open findings by severity and tier, and its governance log. *Unassigned* lists assets no department owns yet. |

## Create a department

1. Open **Configuration > Departments (setup)** and choose **New department**.
2. Enter the name and an optional description.
3. Add people in the **people table** (see below).
4. Press **Create department**.

If something is refused, the form comes back with the reason in a notice that stays, and everything you typed is kept.
If your sign-in had to be renewed while you filled in the form, the page says *Nothing was saved* so you can enter it
again.

## People and roles

Each department has **one people table**: one row per person and role. Choose **+ Add person**, pick the person, and
pick a role. Remove a row with **Remove**. **Save people** saves the whole table in one go, and each change is recorded.

You find people by typing. When directory lookup is on, the list searches your organisation's users and groups. You
can also pick someone already on a department, or type an e-mail address (an outside person, with name and company).

| Role | What the person does |
|---|---|
| **Technical owner** | Fixes things; receives the operational reviews. |
| **Business owner** | Accountable; receives the monthly status report. Needs an e-mail address. |
| **Technical approver** | Approves planning a fix into the department's maintenance window. |
| **Business approver** | Approves accepting a risk raised from the department — including exemption requests made on the department's own page. |
| **Delegate** | Works on the department's findings. |
| **Advisor** | A trusted outside consultant or company advising the owners. Sees this department only. |

*(i) What the roles mean* on the page shows the same list.

**Technical approvers.** When a department has any, only one of them — or someone with the right to approve, such as an
Admin — can apply *Auto in the maintenance window* to the department's findings.

**Business approvers.** They decide the exemption requests raised from the department. See [Exemptions](exemptions).
A person who was an *approver* in an earlier version counts as a business approver.

## Which department owns an asset

The order, highest first:

1. A **recommendation override** (one issue, on every asset).
2. An **asset override** (one asset).
3. The **policy**: the platform tags and/or the **department rules** (pattern rules you add on *Department rules*), in
   the order the settings give.
4. The **default department**, if you set one. Otherwise the asset goes to the **Unassigned** queue.

The order, the tag names and the default department are settings (*Configuration > Settings > Departments & owners*).
Changes apply on the next data sync.

To place many assets at once, select rows on a collection view and choose **Assign to department**.

## A department's page

On **Operations > Departments**, open a department to see:

- its open findings by severity and by tier, and the assets it owns;
- its governance log: comments, recommendations, approvals and planned fixes;
- the action bar on its findings: select rows, then comment, set a status, create a task, or **Request exemption**.

## Remediation flows

On *Configuration > Departments (setup) > Remediation flows*, an Admin defines what happens to a category of findings
for a department. *Auto* plans the fix for the department's next maintenance window and logs it. Nothing is pushed to
Defender, Intune, Entra or Azure. Accepting a risk raises an exemption request that an approver decides. Without a flow,
findings are handled by hand.

## Mails to departments

*Configuration > Settings > Mail & notifications > Mails to departments* turns on the monthly report and the
new-findings digest for each department. A department needs an owner with a mail address.

## Retire a department

**Retire department…** on the department's page asks for a confirmation and a reason. A retired department is hidden by
default (*Hide retired*); its history stays.
