# Security

How SecurityInsight is secured, in one page. The detail is on the pages linked from each section. A full security
review pack for your CISO is published at https://invardia.com/products/securityinsight/security/.

## Principles

1. **Everything runs in your tenant and subscription.** Invardia hosts nothing of yours: no data, no database, no
   runtime. Nothing connects in to your environment; the install only calls out.
2. **Read only towards your tenant.** The engine reads Microsoft Graph, Defender and Azure with read-only permissions.
   The one exception is asset tagging, which has its own identity and writes tags only after you switch writing on.
3. **One identity per role, each with only what its job needs.** See [Identities and permissions](identities-and-permissions).
4. **The engine is one-way.** The web app writes requests and decisions; the engine pulls them and acts. The web app
   can start named jobs but can never change the engine, its image or its database schema.
5. **No secrets in settings.** Every job and app signs in with its managed identity. A secret you supply (an SMTP
   password, an API key) lives only in the install's Key Vault and reaches a job as a Key Vault reference.
6. **Damage is stopped, not cleaned up afterwards.** Safety checks hold large or sudden changes before they reach your
   CMDB, ServiceNow or tickets. See [Guards and guard modes](guards) and [Data health](data-health).

![Who signs in to what: people through Entra sign-in to the web app only; the engine jobs, the web app, the MCP server, the updater and asset tagging each with their own managed identity and only the rights of their job; the optional Invardia Support app through the SQL admin group, its own database user and the Key Vault role of its level](images/identities-access.png)

## Sign-in and roles

- Every user signs in with Entra ID: single sign-on, your MFA and your Conditional Access apply. The enterprise
  application does not require assignment: SecurityInsight decides who has access. Anyone in your directory can sign in,
  and the web app refuses every page to a person it gives no role until a SuperAdmin adds them on the *Access* page. To
  limit who can sign in at all, add a Conditional Access policy for the SecurityInsight enterprise application.
- The sign-in uses the authorisation code flow with PKCE and the web app's managed identity as a federated credential:
  no client secret and no certificate exist to steal or renew. Sessions last at most 8 hours. Every page except a health
  probe requires a signed-in user.
- Four roles, checked on the server for every page and every action: **Reader** (every view, no changes),
  **Delegated** (decisions only inside assigned scopes), **Admin** (everything except roles, licence, updates and
  support access) and **SuperAdmin** (all of it). A kiosk *Wallboard* role sees only the wall board.
- Browser hardening: a strict Content Security Policy, HSTS, framing refused, no referrer, anti-forgery tokens on every
  change.
- Magic links in mails are off by default (they bypass Conditional Access by design).

## Signed requests

Every change a person makes in the web app carries the signed Entra token of that person, stored with the time it was
captured. Before it acts, the engine checks the token's signature against Entra's published keys, the issuer (your
tenant), the audience (the web app), that it was valid when the change was made, and that it is the person who made the
change. Who wrote a change is decided by the database, not by the web app.

- **Observe first.** After the update, SecurityInsight records the configuration that exists (per kind: the number of rows
  and a SHA-256 over them) and only reports what it would refuse, on the audit trail. *Configuration > Signed requests*
  shows "Waiting for adoption by a SuperAdmin".
- **One adoption, signed by a SuperAdmin.** A SuperAdmin adopts exactly the recorded configuration on that page, signed
  with their own sign-in. The engine verifies the signature, that the person is a SuperAdmin and that the hash is the
  recorded one; anything else is refused and the install stays in observe.
- **Then enforced.** A change the engine acts on (settings, documents such as tagging and exclusions, exemptions,
  connectors, overrides, the pipeline, templates, service models and responsibility rules) that carries no verified token
  holds every new pipeline run - a running run is never stopped - until it is undone on *Configuration > Commits* or made
  again signed in; a resend into a connector without one is refused. Each refusal is said in plain words and kept on the
  audit trail. Safety checks, approvals and limits stay on top.

## Pro and Community: the same core security

Every security control is the same in both editions. Pro adds features and support from Invardia, never a security
control; the only difference by design is that Community reports anonymously. Each row names where the control is set in
the source of this release.

| Control | Pro | Community | Where it is set |
|---|---|---|---|
| Sign-in: Microsoft's built-in sign-in in front of the web app, the token verified again by the app | Yes | Yes | pro-management/src/SI.Management.Web/Auth/BuiltInAuth.cs:219 (AuthenticateAsync); the web app is an install step of both editions: setup/_shared/SI-GuidedInstall.ps1:110 |
| Four server-checked roles, and roles and scopes for people and groups (Configuration > Access) | Yes | Yes | pro-management/src/SI.Management.Web/Licensing/ProFeatures.cs:48 (no licence gate on /Admin/Access since this release) |
| Signed requests: the engine verifies the person's signed token before it acts on a change | Yes | Yes | engine/_shared/SI-SignedRequests.ps1:345 (Invoke-SISignedRequestEnforcement; observe until a SuperAdmin-signed adoption); pro-management/src/SI.Management.Web/Audit/AuditFilter.cs:131 |
| One identity per role, each with only its job's rights; the internet-facing web identity holds no job, Key Vault or Graph write right | Yes | Yes | setup/_shared/si-identity-rights.json:118 (internetFacing) |
| SQL least privilege: one role per component (si_engine, si_web, si_mcp, si_updater), no DDL or security right at runtime | Yes | Yes | engine/pro-settings/SI-EngineGrants.ps1:68; pro-management/deploy/SI-ManagementGrants.ps1:15; applied by the database steps of both editions: setup/_shared/SI-GuidedInstallData.ps1:1271 |
| No person as SQL admin: a database setup job does what needed an admin | Yes | Yes | setup/_shared/SI-GuidedInstall.ps1:98 (db-job), one of the steps of both editions (:110) |
| Key Vault: soft delete, purge protection on | Yes | Yes | setup/_shared/SI-GuidedInstall.ps1:3675 |
| Container registry: admin user off, every job pulls with its own identity | Yes | Yes | setup/_shared/SI-GuidedInstall.ps1:3682 (the registry is created with adminUserEnabled false); setup/_shared/SI-SecurityBaseline.ps1:149 (an existing install) |
| SQL auditing to your own workspace, 90 days | Yes | Yes | setup/_shared/SI-GuidedInstallData.ps1:1077 (the security baseline of the database step) |
| Private network: private endpoints, private DNS, public endpoints closed (your choice at install) | Yes | Yes | setup/_shared/SI-GuidedInstall.ps1:100; the only Pro-only install step is the v2.2 CMDB import (:108) |
| Browser hardening: HSTS, Content Security Policy, framing refused, anti-forgery on every change | Yes | Yes | pro-management/src/SI.Management.Web/Program.cs:696 |
| Signed updates: the release verified against keys shipped inside SecurityInsight, then by size and SHA-256 | Yes | Yes | engine/_shared/SI-InvardiaUpdate.ps1:66 (Pro route); engine/_shared/SI-CommunityUpdate.ps1:235 (Community route) - one update client |
| An audit trail the database protects from change, and its viewer (Configuration > History) | Yes | Yes | sql/si-pro-settings.sql:1662; pro-management/src/SI.Management.Web/Licensing/ProFeatures.cs:48 (no licence gate on /Admin/History since this release) |
| Second-person approval of a restore or a guard release (optional setting) | Yes | Yes | sql/si-pro-settings.sql:2696 (cfg.ConfigApproval) |
| Support access by the Invardia Support app: optional, off until you create it, at the level you choose | Yes | Yes | setup/_shared/SI-GuidedInstall.ps1:97 (support-app-access) |

## Network

- The web app is reachable either from the internet behind Entra sign-in (add Conditional Access) or from your
  network only. Your choice at install.
- No virtual network is created by default; adding one with private endpoints is supported and recommended for strict
  networks.
- Storage, Key Vault and SQL are reached with managed identities. The storage account has shared-key access off. The
  database accepts Entra identities only.

## The database

Entra-only authentication, one contained database user per component, one least-privilege role per component, no
standing DDL or security right on any runtime identity, and SQL auditing to your own workspace for 90 days. The audit
trail cannot be changed or deleted, enforced by the database itself. See [SQL access](sql-access).

## Secrets and keys

| What | Where |
|---|---|
| Licence, install key, connector secrets, optional keys (Shodan, SMTP password) | The install's Key Vault, purge protection on |
| Azure OpenAI | No key is needed: SecurityInsight signs in to your Azure OpenAI resource with its own identities, which need the role Cognitive Services OpenAI User that you or your support partner give. A key an older setup still keeps stays in the Key Vault and is used only when that sign-in is refused. |
| A secret you paste in the web app | Handed encrypted to the updater, which stores it in the Key Vault. The web app itself never writes a secret. |
| The container registry | Admin user off; every job pulls with its own identity |

## Updates and integrity

- Releases are signed by Invardia and verified by the install against public keys that ship inside SecurityInsight,
  then checked by size and SHA-256. Images are built from the verified source inside your own registry.
- A release reaches rings in order: 0 Dev, 1 Test, 2 Design partners, 3 Broad. A release to rings 2 and 3 needs the
  vendor's release owner's explicit approval, and is held while installs that took it report unhealthy data. See
  [Releases, rings and waves](releases).
- For 24 hours after a release that changed engine code, every numbered safety check is twice as strict.
- The licence is signed and verified offline, bound to the tenant of the identity's own token. A licence copied to
  another tenant does not unlock Pro.

## Change control and audit

- Changes in the web app are staged and written only on *Review & commit*, each in one transaction with an audit row.
- A change a job carries out names the person who asked for it, and the approver.
- Exemptions are requested, approved by the domain's owners, reviewed monthly and ended, never deleted.
- One deviation report lists every override, exemption, exclusion, disabled detection and changed setting.

## Vendor access

Invardia can reach your install only through the Invardia Support app, which exists only if you create it, at the
level you choose, and which you can disable or remove at any time. Every support action is recorded. See
[Support access](support-access).

## Scripts

Every script a person runs has a documentation page at https://invardia.com/docs/si/scripts/ (purpose, the rights it
needs, every change it makes, how to undo it), supports `-WhatIf` or plans by default, keeps a transcript, carries
everything it runs (no second download) and is listed with its SHA-256 in `SHA256SUMS.txt`.
