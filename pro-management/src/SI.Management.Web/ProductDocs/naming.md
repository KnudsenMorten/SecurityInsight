# Naming

SecurityInsight follows one naming convention, shared by every Invardia product: **a short code in Azure, the full name
where people read.** The product code is `si`. Names never carry the environment or the update ring; the resource group
and its tags say which environment an install is.

## Azure resources and identities

| Kind | Pattern | SecurityInsight |
|---|---|---|
| Container app | `ca-<code>-<purpose>` | `ca-si-web` (the web app), `ca-si-mcp` (the MCP server) |
| Container Apps job | `caj-<code>-<purpose>` | `caj-si-<step>` for each pipeline step, `caj-si-updater` |
| Managed identity | `id-<code>-<role>` | `id-si-engine`, `id-si-web`, `id-si-mcp`, `id-si-updater`, `id-si-tagging` |
| Entra group | `grp-<code>-<purpose>` | `grp-si-sql-admins` |

The purpose words are the same in every product: `engine`, `web`, `updater`, `mcp`.

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

- **Resources keep their names** on an install made before this convention. A new install gets the new names.
- **Display names are renamed by the update** on every install: the engine application first, then the sign-in
  application, and the SQL admin group's display name -- only from SecurityInsight's earlier name; a name you chose is kept.
  Each is renamed once, read back, and put back if it does not take. Where the update may not rename them, an
  administrator runs `Set-SIDisplayNames.ps1`. The mail sender's display name has always been *SecurityInsight*.
- **Never renamed:** the mail sender's address and the Exchange scope that limits sending to it, because your own mail
  rules may refer to them.
- **An install is never half-renamed.** When an install's resource group already holds any component under the earlier
  names, every component keeps the earlier names, also when setup is run again.

SecurityInsight never finds its own resources by a name written into its code. Every install records the names it runs
with, and every part of SecurityInsight reads them from that record, so earlier and new names work side by side.

| Component | Earlier name | New install |
|---|---|---|
| The web app | `ca-si-management` | `ca-si-web` |
| The MCP server, the updater job, the pipeline steps | `ca-si-mcp`, `caj-si-updater`, `caj-si-<step>` | unchanged |
| The engine's identity | `id-si-<ring>-<edition>-<hosting>` | `id-si-engine` |
| The web app's identity | `uami-si-management` | `id-si-web` |
| The MCP server's identity | `uami-si-mcp` | `id-si-mcp` |
| The updater's identity | `uami-si-updater` | `id-si-updater` |
| Asset tagging's identity | `uami-securityinsight-tagging` | `id-si-tagging` |
| The sign-in application | *SecurityInsight Management* | *SecurityInsight* (an existing install keeps the earlier name until its update renames it) |
| The engine application | *SecurityInsight* | *SecurityInsight Engine* (an existing install keeps the earlier name until its update renames it) |
| The SQL admin group | `grp-si-sql-admins` | `grp-si-sql-admins`, shown as *SecurityInsight SQL admins* |
