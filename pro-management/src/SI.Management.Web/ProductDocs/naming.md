# Naming

SecurityInsight follows one naming convention, shared by every Invardia product: **a short code in Azure, the full name
where people read.** The product code is `si`. Names never carry the environment or the update ring; the resource group
and its tags say which environment an install is.

## Azure resources and identities

| Kind | Pattern | SecurityInsight |
|---|---|---|
| Container app | `ca-<code>-<purpose>` | `ca-si-management` (the web app), `ca-si-mcp` (the MCP server) |
| Container Apps job | `caj-<code>-<purpose>` | `caj-si-<step>` for each pipeline step, `caj-si-updater` |
| Managed identity | `id-<code>-<role>` | `id-si-engine`, `id-si-web`, `id-si-mcp`, `id-si-updater`, `id-si-tagging` |
| Entra group | `grp-<code>-<purpose>` | `grp-si-sql-admins` |

The purpose words are the same in every product: `engine`, `web`, `updater`, `mcp`. The web app is the one exception:
it is `ca-si-management` at every install, so its address stays the one your people know.

## Where people read

| What | Name |
|---|---|
| The web app's sign-in application (app registration and enterprise application) | **SecurityInsight** |
| SecurityInsight's engine application, where the install has one | **SecurityInsight Engine** |
| The SQL admin group's display name | **SecurityInsight SQL admins** |
| The mail sender's display name | **SecurityInsight** |
| The product in every page, mail subject and report | **SecurityInsight** |
| The Support app | **Invardia Support** |

## Existing installs

Azure cannot rename a container app, a job, a managed identity, a SQL server, a Key Vault or a registry. So:

- **Container apps, jobs and the other resources keep their names.** The update moves each managed identity to its
  standard name, one install at a time: it creates the new identity, gives it the same rights, switches over, and removes
  the earlier identity only once the new one is proven.
- **Display names are renamed by the update** on every install: the engine application first, then the sign-in
  application, and the SQL admin group's display name - only from SecurityInsight's earlier name; a name you chose is kept.
  Each is renamed once, read back, and put back if it does not take. Where the update may not rename them, an
  administrator runs `Set-SIDisplayNames.ps1`. The mail sender's display name has always been *SecurityInsight*.
- **Never renamed:** the mail sender's address and the Exchange scope that limits sending to it, because your own mail
  rules may refer to them.
- **An install is never half-renamed.** When an install's resource group already holds any component under the earlier
  names, every component keeps the earlier names, also when setup is run again.

SecurityInsight never finds its own resources by a name written into its code. Every install records the names it runs
with, and every part of SecurityInsight reads them from that record, so earlier and new names work side by side.

<!-- naming-table -->
| Role | Standard name | Earlier name | Identity |
|---|---|---|---|
| The pipeline and its steps (the engine jobs) | `caj-si-flow`, `caj-si-<step>` for each step | - | `id-si-engine` (earlier: `id-si-<ring>-<edition>-<hosting>`) |
| The updater job | `caj-si-updater` | - | `id-si-updater` (earlier: `uami-si-updater`) |
| The database job | `caj-si-dbinit` | - | `id-si-dbinit` |
| The asset tagging job | `caj-si-asset-tagging` | - | `id-si-tagging` (earlier: `uami-securityinsight-tagging`) |
| The web app | `ca-si-management` | - (unchanged: the web app keeps its name and address at every install) | `id-si-web` (earlier: `uami-si-management`) |
| The MCP server | `ca-si-mcp` | - | `id-si-mcp` (earlier: `uami-si-mcp`) |
| The SQL admin group | `grp-si-sql-admins`, shown as *SecurityInsight SQL admins* | - | - |
| The sign-in application | *SecurityInsight* | *SecurityInsight Management* (until the update renames it) | - |
| The engine application, where the install has one | *SecurityInsight Engine* | *SecurityInsight* (until the update renames it) | - |
<!-- /naming-table -->
