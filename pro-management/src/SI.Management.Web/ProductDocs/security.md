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
5. **No secrets in settings.** Every job and app signs in with its managed identity: no password, client secret or
   certificate is created for them. The secrets that exist are the install key and what you supply (an SMTP password, an
   API key, a connector credential); they live only in the install's Key Vault and reach a job as a Key Vault reference.
   The Invardia Support app, if you create it, signs in with a client secret that Invardia holds, never in your install.
6. **Damage is stopped, not cleaned up afterwards.** Safety checks hold large or sudden changes before they reach your
   CMDB, ServiceNow or tickets. See [Guards and guard modes](guards) and [Data health](data-health).

![Who signs in to what: people through Entra sign-in to the web app only; the engine jobs, the web app, the MCP server, the updater and asset tagging each with their own managed identity and only the rights of their job; the optional Invardia Support app with its own read-only database user, more only just in time, and the Key Vault role of its level](images/identities-access.png)

## Sign-in and roles

- Every user signs in with Entra ID: single sign-on, your MFA and your Conditional Access apply. The enterprise
  application does not require assignment: SecurityInsight decides who has access. Anyone in your directory can sign in,
  and the web app refuses every page to a person it gives no role until a SuperAdmin adds them on the *Access* page. To
  limit who can sign in at all, add a Conditional Access policy for the SecurityInsight enterprise application.
- The web app checks the signed-in person and their SecurityInsight role on every request. The sign-in app
  registration uses the web app's managed identity as a federated credential: no client secret and no certificate are
  created for it. Every page except a health probe requires a signed-in user.
- Four roles, checked on the server for every page and every action: **Reader** (every view, no changes),
  **Delegated** (decisions only inside assigned scopes), **Admin** (everything except roles, licence, updates and
  support access) and **SuperAdmin** (all of it). A kiosk *Wallboard* role sees only the wall board.
- Browser hardening: a Content Security Policy that allows scripts, styles and connections from the app itself only,
  HSTS, framing refused, no referrer, anti-forgery tokens on every
  change.
- Sign-in links in mails are off by default; keep them off so every access goes through Conditional Access.

## Pro and Community: the same core security

Every security control is the same in both editions. Pro adds features and support from Invardia, never a security
control; the only difference by design is that an unconnected Community install reports anonymously.

| Control | Pro | Community |
|---|---|---|
| Sign-in: Microsoft Entra ID before every page, the person's SecurityInsight role checked on the server | Yes | Yes |
| Four server-checked roles, and roles and scopes for people and groups (Configuration > Access) | Yes | Yes |
| One identity per role, each with only its job's rights; the internet-facing web identity holds no job, Key Vault or Graph write right | Yes | Yes |
| SQL least privilege: one role per component (si_engine, si_web, si_mcp, si_updater), no DDL or security right at runtime | Yes | Yes |
| No person as SQL admin: a database setup job does what needed an admin | Yes | Yes |
| Key Vault: soft delete, purge protection on | Yes | Yes |
| Container registry: admin user off, every job pulls with its own identity | Yes | Yes |
| SQL auditing to your own workspace, 90 days | Yes | Yes |
| Private network: private endpoints, private DNS, public endpoints closed (your choice at install) | Yes | Yes |
| Browser hardening: HSTS, Content Security Policy, framing refused, anti-forgery on every change | Yes | Yes |
| Signed updates: the release verified against keys shipped inside SecurityInsight, then by size and SHA-256 | Yes | Yes |
| An audit trail the database protects from change, and its viewer (Configuration > History) | Yes | Yes |
| Second-person approval of a restore or a guard release (optional setting) | Yes | Yes |
| Support access by the Invardia Support app: optional, off until you create it, at the level you choose | Yes | Yes |

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
- An install takes releases from the early-release channel (ring 2) or the standard channel (ring 3, the default). A
  version reaches either only after SecurityInsight has built, tested and verified it and a recorded release approval,
  and it is held while installs that took it report unhealthy data. See
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
