# Provider Plugin Contract

> **Spec**: ARCHITECTURE.md § 6. A provider is a self-contained plugin folder
> under `v2.2/asset-profiling-providers/<name>/`. The engine talks to providers via 4 well-
> known PowerShell functions. Adding a new data source = new folder; no
> engine code changes.

## Folder layout

```
v2.2/asset-profiling-providers/<name>/
  manifest.locked.json         Required. Conforms to _manifest.schema.locked.json.
  Test-Connection.ps1          Required. Exports Test-<Name>ProviderConnection.
  Read.ps1                     Required when manifest.kind includes 'in'.
                               Exports Read-<Name>ProviderData -Engine X.
  Write.ps1                    Required when manifest.kind includes 'out'.
                               Exports Write-<Name>ProviderData -Engine X -Rows.
  Connect.ps1                  Optional helper exposing connection setup.
  schema-fragment.json         Optional. Provider-specific schema additions.
  sample/                      Optional. Sample data for offline testing.
```

## manifest.json

| Field          | Type    | Required | Notes                                                                  |
|----------------|---------|----------|------------------------------------------------------------------------|
| `id`           | string  | yes      | Lowercase, dash-separated. Matches the folder name.                    |
| `kind`         | string  | yes      | `in` (read-only data source), `out` (sink), or `both` (read + write).  |
| `engines`      | array   | yes      | Engines this provider serves (`identity`, `endpoint`, `azure`, `publicip`). |
| `auth`         | object  | yes      | `{ type: spn|umi|api-key|none, scopes: [...] }`                         |
| `bulk`         | bool    | yes      | `true` when `Read-...` returns all assets in N pages (no per-asset calls). |
| `rateLimit`    | object  | optional | `{ calls: N, per: '60s' }` for hint-only client throttle.              |
| `description`  | string  | optional | One-line summary.                                                      |

## Required functions

Every provider MUST export these (regardless of `kind`):

```powershell
function Get-<Name>ProviderManifest { <# returns manifest.json content as a hashtable #> }

function Test-<Name>ProviderConnection {
    <# Returns @{ Ok=<bool>; Error=<string?>; Detail=<string?> }.
       Must NOT throw on transport errors -- swallow + report via Ok=false.
       Should make ONE lightweight call (e.g. /me, $top=1, count=...).
    #>
}
```

When `kind` includes `in`:

```powershell
function Read-<Name>ProviderData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter()]$RunContext
    )
    <# Returns array of [hashtable] / [pscustomobject] asset rows for $Engine.
       Use the engine's profile schema (profiles/<engine>.schema.json) field
       names. Bulk-fetch in pages; do NOT loop per-asset.
    #>
}
```

When `kind` includes `out`:

```powershell
function Write-<Name>ProviderData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter()]$RunContext
    )
    <# Pushes $Rows to the destination. Idempotent (same rows twice = same
       end state). Returns @{ Sent=<int>; Failed=<int>; Errors=[...] }.
    #>
}
```

## Engine integration

Stage Profile (and the new Reconcile phase, ) discovers providers
by scanning `providers/*/manifest.json`. For each manifest:
1. Filters by `engines` matching the current engine
2. Calls `Test-<Name>ProviderConnection` (skips on Ok=false)
3. For `kind` in (`in`, `both`): calls `Read-<Name>ProviderData -Engine X`
4. For `kind` in (`out`, `both`): calls `Write-<Name>ProviderData -Engine X -Rows $finalRows`

The schema declares which providers each engine USES via
`providers.in[]` / `providers.out[]`. Engine refuses to run if a declared
provider is missing.

## Reference implementation

See `providers/entra/` for a working example. It wraps the existing
`discovery/Get-DiscoveryFromEntra*.ps1` functions in the provider contract.
