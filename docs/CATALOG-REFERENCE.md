# SecurityInsight -- Privilege-tier catalog JSON reference

This is the **single source of truth** for `privilege-tier-catalog.locked.json` -- the AI-classified inventory of every Active Directory group, Entra role, Graph API permission, and Azure RBAC role, scored on the attacker-centric Tier 0..3 scale.

> **Authority**: validated against `engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1` (the producer) and `engine/asset-profiling/shared/IdentityCatalogTierComputer.ps1` (the consumer, lines 84-496). When code disagrees with this doc, code wins.

---

## File pair

| File | Purpose | Edited by |
|---|---|---|
| `privilege-tier-catalog/privilege-tier-catalog.locked.json` | Classifier output (AI-generated baseline) | `Invoke-PrivilegeTierClassifier.ps1` regenerates it |
| `asset-profiling-enrichment/identity/PrivilegeTierClassifier.json` (optional) | Customer overlay -- adds tenant-custom AD groups, Entra/Azure custom roles | Customer |

The overlay is loaded by `IdentityCatalogTierComputer.ps1` lines 118-147 if present; absence is silent.

---

## Tier scale (attacker-centric)

| Tier | Means | Examples |
|---|---|---|
| **0** | One-step compromise of the identity plane / tenant | Domain Admins; Global Administrator; Privileged Role Administrator; Directory.ReadWrite.All |
| **1** | Privilege-escalation path (multi-step) | Backup Operators; Server Operators; Helpdesk Administrator; Owner (subscription) |
| **2** | Workload / data impact, no direct identity-plane path | Hyper-V Administrators; DnsAdmins; Reports Reader; Contributor on a single resource |
| **3** | Standard accounts -- no escalation path | Users; Authenticated Users; Domain Users; Reader |

`Get-SIMinTier` (consumer line 489-496) reduces over all signal sources for one identity and returns the **lowest tier number** (= highest privilege). When all sources return `$null`, default is **Tier 3**.

---

## Top-level structure

```json
{
  "Metadata": { ... },
  "AD_BuiltInPermissionGroups_Tier0":  [ ... ],
  "AD_BuiltInPermissionGroups_Tier1":  [ ... ],
  "AD_BuiltInPermissionGroups_Tier2":  [ ... ],
  "AD_BuiltInPermissionGroups_Tier3":  [ ... ],
  "AD_CustomGroups_Tier0":             [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...],
  "EntraID_BuiltInRoles_Tier0":        [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...],
  "EntraID_CustomRoles_Tier0":         [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...],
  "EntraID_APIPermissions_Tier0":      [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...],
  "Azure_BuiltInRoles_Tier0":          [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...],
  "Azure_CustomRoles_Tier0":           [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...]
}
```

### `Metadata` envelope

| Field | Type | Required | Read by |
|---|---|---|---|
| `GeneratedAt` | string (ISO 8601) | yes | `IdentityCatalogTierComputer.ps1:55` (freshness check) |
| `GeneratedBy` | string | yes | docs only |
| `TenantId` | string (GUID) | yes | docs only |
| `TieringModel` | string | yes | docs only |
| `AICallsUsed` | int | yes | docs only -- one Azure OpenAI batch per provider category (typically 4) |

---

## Per-entry shape

Different sections use different key fields. The merge between locked + custom uses these keys (case-insensitive).

### AD groups (`AD_*Groups_Tier*`)

| Key | Type | Required | Merge key | Read by |
|---|---|---|---|---|
| `Name` | string | yes | YES | `IdentityCatalogTierComputer.ps1:248,354` (lowercased lookup) |
| `Tier` | int 0..3 | yes | no | `IdentityCatalogTierComputer.ps1:356` |
| `Reason` | string | yes | no | shown in audit logs (line 427) |

### Entra roles (`EntraID_*Roles_Tier*`)

| Key | Type | Required | Merge key | Read by |
|---|---|---|---|---|
| `DisplayName` | string | yes | YES | `IdentityCatalogTierComputer.ps1:177` |
| `Tier` | int 0..3 | yes | no | line 379 |
| `Description` | string | optional | no | docs only -- AI uses it as classifier context |

### API permissions (`EntraID_APIPermissions_Tier*`)

| Key | Type | Required | Merge key | Read by |
|---|---|---|---|---|
| `Value` | string | yes | YES | `IdentityCatalogTierComputer.ps1:203,341` (HashSet O(1) lookup) |
| `Tier` | int 0..3 | yes | no | line 341 |
| `Description` | string | optional | no | docs only |

Example `Value`: `Directory.ReadWrite.All`, `Mail.Send`, `RoleManagement.ReadWrite.Directory`.

### Azure roles (`Azure_*Roles_Tier*`)

| Key | Type | Required | Merge key | Read by |
|---|---|---|---|---|
| `Name` | string | yes | YES | `IdentityCatalogTierComputer.ps1:282` |
| `Tier` | int 0..3 | yes | no | line 407 |
| `Description` | string | optional | no | docs only |

---

## Default tier behaviour (no-match)

| Provider | Lookup miss with non-empty input | Lookup miss with empty input |
|---|---|---|
| Entra roles | **Tier 2** (line 335) | `$null` |
| API permissions | **Tier 2** (line 345) | `$null` |
| AD groups | `$null` (line 369) | `$null` |
| Azure roles | **Tier 2** (line 369) | `$null` |

`Get-SIMinTier` (line 489-496):
- Excludes `$null` and `-1`.
- Returns the smallest remaining number.
- If every signal is `$null`, returns **3** (safest fallback).

---

## Customer overlay -- how to add tenant-custom roles

Create `asset-profiling-enrichment/identity/PrivilegeTierClassifier.json` (anywhere the identity engine can find it -- this is the canonical path the consumer looks up first). Same shape as the catalog file; you only need the sections you want to add to:

```json
{
  "AD_CustomGroups_Tier0": [
    { "Name": "ORG-DomainBreakGlass", "Tier": 0,
      "Reason": "Custom break-glass group with domain-wide reset rights." }
  ],
  "AD_CustomGroups_Tier1": [
    { "Name": "ORG-PrintOps", "Tier": 1,
      "Reason": "Print-spooler service control -- known PrintNightmare escalation surface." }
  ],
  "EntraID_CustomRoles_Tier1": [
    { "DisplayName": "Custom Compliance Officer", "Tier": 1,
      "Description": "Tenant-custom role; limited audit scope but can read sensitive policies." }
  ],
  "Azure_CustomRoles_Tier0": [
    { "Name": "ORG-OnCallTenantOwner", "Tier": 0,
      "Description": "Custom role with Owner+UserAccessAdministrator at tenant root." }
  ]
}
```

**Merge** (line 118-147):
- Same merge key in same section -> custom **REPLACES** locked entry.
- New key -> **APPENDED**.
- Sections you don't list are untouched.

---

## How the catalog is generated

`engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1` (output: `privilege-tier-catalog/privilege-tier-catalog.locked.json`).

Runs in 4 stages, one batched Azure OpenAI call per stage:

1. **Stage A** -- enumerate AD built-in groups (no member collection).
2. **Stage B** -- enumerate Entra role definitions (built-in + custom).
3. **Stage C** -- enumerate Microsoft Graph API permissions from well-known service principals.
4. **Stage D** -- enumerate Azure RBAC role definitions (built-in + custom).

Each stage POSTs name + description to Azure OpenAI with the attacker-centric framework prompt; classifier returns `Tier` (0..3) and an optional `Reasoning`. Stages then write into the appropriate `*_Tier{0..3}` arrays.

When to re-run:
- New custom AD group / Entra role / Azure RBAC role created.
- New tenant onboarding.
- Microsoft adds new built-in roles (rare but happens; check release notes).

The classifier requires Azure OpenAI credentials -- defaults: `AI_ChunkSize=50`, `AI_MaxRetries=3`, `AI_MaxTokens=16384` (set silently at script top).

---

## Engine consumers (where the catalog is read)

| File | Lines | Reads |
|---|---|---|
| `engine/asset-profiling/shared/IdentityCatalogTierComputer.ps1` | 84-496 | All sections; computes per-identity `Get-SITierFromEntraRoles`, `Get-SITierFromEntraAPIPerms`, `Get-SITierFromADGroups`, `Get-SITierFromAzureRoles`; reduces via `Get-SIMinTier` |
| `engine/asset-profiling/shared/Build-IdentityProfileRow.ps1` | per-identity emit | Reads computed tier + writes `Tier` column |

Endpoints don't read this catalog directly -- they use a separate `EndpointCatalogTierComputer.ps1` keyed on machine roles.

---

## See also

- [`../asset-profiling-enrichment/RULE-REFERENCE.md`](../asset-profiling-enrichment/RULE-REFERENCE.md) -- AssetProfileBy* rules (which can reference the same identities)
- [`../asset-profiling-schema/SCHEMA-REFERENCE.md`](../asset-profiling-schema/SCHEMA-REFERENCE.md) -- the Tier column lives in `SI_Identity_Profile_CL` per `identity.schema.locked.json`
- `engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1` -- the producer
