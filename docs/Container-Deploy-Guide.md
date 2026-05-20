# SecurityInsight — Cloud-Only Container Deployment & Operations Guide

End-to-end recipe for a **VM-less** SecurityInsight install: everything runs as
Azure Container App Jobs (ACR image + KEDA-scaled per-engine jobs). No
launcher VM required.

This is the procedure used for `rg-sicontainertest` (Community flavour).

---

## 1. Prerequisites (one-time)

| Requirement                                  | Notes                                                                   |
|----------------------------------------------|-------------------------------------------------------------------------|
| Azure subscription with Owner / RBAC Admin   | Needed to grant SPN RBAC and create Container Apps Env + ACR            |
| Tenant Global Admin (or Privileged Role Admin) | For `New-SISpn` Graph admin-consent step                              |
| `az` CLI installed                           | `Bootstrap-ContainerAppJob` shells out to `az acr build`                |
| `Az` PowerShell + `Microsoft.Graph` modules  | PS 5.1 or pwsh 7                                                        |
| Key Vault `kv-<suffix>` in target RG          | Pre-create with **RBAC mode** (modern default); operator must have `Key Vault Administrator` on it |

Pre-create the KV:

```powershell
function global:New-Guid { [System.Guid]::NewGuid() }   # PS 5.1 shim
New-AzKeyVault -VaultName 'kv-sicont' `
               -ResourceGroupName 'rg-sicontainertest' `
               -Location 'westeurope' `
               -Sku Standard `
               -EnablePurgeProtection `
               -SoftDeleteRetentionInDays 7
# Operator RBAC
$me = (Get-AzADServicePrincipal -ApplicationId (Get-AzContext).Account.Id).Id
New-AzRoleAssignment -ObjectId $me `
                     -RoleDefinitionName 'Key Vault Administrator' `
                     -Scope (Get-AzKeyVault -VaultName 'kv-sicont').ResourceId
```

---

## 2. Author `config/setup-unattended.json`

Copy `config/setup-unattended.sample.json` -> `config/setup-unattended.json`
and edit. Minimum **cloud-only Community + Container** shape:

```jsonc
{
  "Flavour": "Community",
  "Sub": {
    "TenantId":       "<tenant-guid>",
    "SubscriptionId": "<sub-guid>",
    "Location":       "westeurope"
  },
  "Resources": {
    "ResourceGroupName":  "rg-sicontainertest",
    "WorkspaceName":      "log-sicont",
    "DceName":            "dce-sicont",
    "StorageAccountName": "stsicont",
    "NamingSuffix":       null
  },
  "Auth_Community": {
    "DisplayName":  "sicontainertest",
    "CredKind":     "Secret",
    "CredStorage":  "KeyVault",
    "KeyVaultName": "kv-sicont"
  },
  "Container": {
    "Enabled":         true,
    "AcrName":         "acrsicont",
    "EnvName":         "cae-sicont",
    "UseKEDA":         true,
    "KedaMaxReplicas": 30
  }
}
```

Storage account names must be ≤24 chars, lowercase alphanumeric. Workspace and
DCE names follow the standard rules.

---

## 3. Run the unattended deploy

Two ways to call `Setup-SecurityInsight-Unattended.ps1`:

### A. Interactive Community (browser auth) — the original path

```powershell
Connect-AzAccount -Tenant <tenant> -Subscription <sub>
Connect-MgGraph   -TenantId <tenant>
az login --tenant <tenant>
cd C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight
.\Setup-SecurityInsight-Unattended.ps1 -Flavour Community -Container_Enabled
```

### B. Non-interactive Community (reuse existing SPN context) — sicont path

Pre-connect Az PS + Mg Graph + az CLI with any high-privilege SPN, then call
the unattended script with no extra flags. The script's Community block now
detects an existing matching Az+Mg context and reuses it.

```powershell
function global:New-Guid { [System.Guid]::NewGuid() }
Import-Module 'C:\SCRIPTS\AutomateIT\FUNCTIONS\AutomateITPS\AutomateITPS.psd1' -Force
Connect-Platform  # connects Modern SPN to Az + Mg via the v1 KV

az login --service-principal --tenant $global:AzureTenantId `
         --username $global:HighPriv_Modern_ApplicationID_Azure `
         --password $global:HighPriv_Modern_Secret_Azure --output none
az account set --subscription '<sub-guid>'

cd C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight
.\Setup-SecurityInsight-Unattended.ps1 -Flavour Community -Container_Enabled
```

The script runs 5 phases:

| Phase | Cmdlet                       | What it does                                                                 |
|-------|------------------------------|------------------------------------------------------------------------------|
| 1     | `New-SISpn`                  | Creates/reuses SPN + rotates client secret + grants Graph/MTP/MDE perms + tenant-root Reader RBAC + stores secret in KV |
| 2     | `Initialize-SIInfra`         | Log Analytics workspace + DCE + Storage account + DCR per Profile table + RBAC for SPN |
| 2.5   | (Internal only)              | Seed v1 KV with `SI-Shodan-ApiKey` + `OpenAI-ApiKey`                          |
| 3     | `Write-SICustomConfig`       | Renders `config/SecurityInsight.custom.ps1` (Community = inline values)       |
| 4     | `Set-SIEntraDiagnosticSetting` | Skipped unless `EntraDiag.Enabled = true`                                  |
| 5     | `Initialize-SIContainerInfra` | Provisions ACR, builds image via `az acr build`, creates Container Apps Env, creates 1-2 jobs per engine, sets up KEDA queue scalers |

End state: 1 ACR + 1 CAE + per-engine Container App Jobs in the RG.

---

## 4. Jobs created (KEDA mode, default)

Each engine gets two jobs (except the two RA jobs, which are single-replica report builds):

| Engine                     | Producer (cron-triggered)                | Worker (KEDA queue-scaled)                | Default cron (UTC) |
|----------------------------|------------------------------------------|-------------------------------------------|--------------------|
| endpoint                   | `caj-si-endpoint-producer`               | `caj-si-endpoint-worker`                  | 04:00 daily        |
| identity                   | `caj-si-identity-producer`               | `caj-si-identity-worker`                  | 04:30 daily        |
| azure                      | `caj-si-azure-producer`                  | `caj-si-azure-worker`                     | 05:00 daily        |
| schema-discovery           | `caj-si-schema-discovery-producer`       | `caj-si-schema-discovery-worker`          | 03:00 every Sunday |
| risk-analysis (Summary)    | `caj-si-risk-analysis` (single, no worker) | —                                       | 06:00 daily        |
| risk-analysis (Detailed)   | `caj-si-risk-analysis-detailed` (single, no worker) | —                              | 08:00 daily        |
| privilege-tier-classifier  | `caj-si-ptc-producer`                    | `caj-si-ptc-worker`                       | 04:00 daily        |
| publicip                   | `caj-si-publicip-producer`               | `caj-si-publicip-worker`                  | 04:00 daily        |

**Why two RA jobs?** Summary is the daily exec-friendly roll-up (small, ~1–10K rows). Detailed is the per-asset finding inventory the SecOps team actually drills into (much larger, ~100K+ rows). Both share the same engine + image; they differ only in `SI_RA_MODE` env (`Summary` vs `Detailed`) and `SI_RA_REPORT_TEMPLATE` (`RiskAnalysis_Summary` vs `RiskAnalysis_Detailed_Bucket`). Detailed runs 2h after Summary so the LA workspace isn't double-loaded.

The producer drops shard messages onto `si-<engine>-shards` Storage Queue.
KEDA scales the worker from 0 to `KedaMaxReplicas` (default 30) based on queue
depth, then scales back to zero when the queue drains.

---

## 5. How to **start** a job manually (no waiting for cron)

```powershell
# Start one engine right now
az containerapp job start --name caj-si-endpoint-producer --resource-group rg-sicontainertest
az containerapp job start --name caj-si-risk-analysis    --resource-group rg-sicontainertest

# Or via PowerShell wrapper
Invoke-AzRestMethod -Method POST `
  -Path "/subscriptions/<sub>/resourceGroups/rg-sicontainertest/providers/Microsoft.App/jobs/caj-si-endpoint-producer/start?api-version=2024-03-01"
```

For a full Profilers + RA chain (run in order, wait between):

```powershell
$rg = 'rg-sicontainertest'
foreach ($e in 'endpoint','identity','azure','publicip') {
    az containerapp job start --name "caj-si-$e-producer" --resource-group $rg
}
# wait until the worker queues drain (see § 6), then:
az containerapp job start --name 'caj-si-ptc-producer'             --resource-group $rg
az containerapp job start --name 'caj-si-risk-analysis'            --resource-group $rg   # Summary
az containerapp job start --name 'caj-si-risk-analysis-detailed'   --resource-group $rg   # Detailed
```

---

## 6. How to **monitor** an execution

```powershell
# List recent executions of a job
az containerapp job execution list --name caj-si-endpoint-worker --resource-group rg-sicontainertest --query '[].{name:name, status:properties.status, started:properties.startTime}' -o table

# Stream logs of latest execution
$exec = az containerapp job execution list --name caj-si-endpoint-worker --resource-group rg-sicontainertest --query '[0].name' -o tsv
az containerapp job logs show --name caj-si-endpoint-worker --resource-group rg-sicontainertest --execution $exec --container caj-si-endpoint-worker --follow

# Queue depth (drives KEDA scale-up)
az storage message peek --queue-name si-endpoint-shards --account-name stsicont --num-messages 5 --auth-mode login
```

In Log Analytics:

```kql
ContainerAppConsoleLogs_CL
| where ContainerAppName_s startswith "caj-si-"
| order by TimeGenerated desc
```

---

## 7. How to **change the schedule**

Two paths. Both are no-rebuild — the cron lives on the Container App Job, not in the image.

### A. Edit `config/SecurityInsight.custom.ps1` then re-run Bootstrap

Set any of these globals (all are pure cron strings, UTC):

```powershell
$global:SI_Bootstrap_ScheduleEndpoint             = '0 */6 * * *'   # every 6h
$global:SI_Bootstrap_ScheduleIdentity             = '15 */6 * * *'
$global:SI_Bootstrap_ScheduleAzure                = '30 */6 * * *'
$global:SI_Bootstrap_ScheduleRiskAnalysis         = '0 6 * * *'     # 06:00 UTC daily Summary
$global:SI_Bootstrap_ScheduleRiskAnalysisDetailed = '0 8 * * *'     # 08:00 UTC daily Detailed
$global:SI_Bootstrap_ScheduleSchemaDiscovery      = '0 3 * * 0'
```

Then re-run the bootstrap (it's idempotent; only touches the cron field on
existing jobs):

```powershell
cd C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight
.\Bootstrap-ContainerAppJob.ps1
```

### B. One-off `az` update on a single job

```powershell
az containerapp job update --name caj-si-endpoint-producer --resource-group rg-sicontainertest --cron-expression "0 */4 * * *"
```

### Disable a schedule (run only on demand)

```powershell
az containerapp job update --name caj-si-risk-analysis --resource-group rg-sicontainertest --cron-expression ""
```

(blank cron disables auto-trigger; `az containerapp job start` still works)

---

## 8. How to **scale up** under load

KEDA scales workers based on queue depth. Adjust the cap:

```powershell
az containerapp job update --name caj-si-endpoint-worker --resource-group rg-sicontainertest --max-executions 60
```

Or globally on next bootstrap:

```powershell
$global:SI_Bootstrap_KedaMaxReplicas = 60
.\Bootstrap-ContainerAppJob.ps1
```

---

## 9a. How are PowerShell modules pre-staged in the image?

`container/Dockerfile` has one `RUN pwsh ... Install-Module -RequiredVersion ...`
layer that installs every module the engines need, pinned to exact versions:

```dockerfile
FROM mcr.microsoft.com/powershell:lts-ubuntu-22.04
RUN pwsh -NoProfile -Command \
    "Install-Module -Name Az.Accounts            -RequiredVersion 5.4.0 -Force -Scope AllUsers; \
     Install-Module -Name Az.Resources           -RequiredVersion 9.0.3 -Force -Scope AllUsers; \
     Install-Module -Name Az.Storage             -RequiredVersion 9.6.0 -Force -Scope AllUsers; \
     Install-Module -Name Az.Monitor             -RequiredVersion 7.0.0 -Force -Scope AllUsers; \
     Install-Module -Name Az.ResourceGraph       -RequiredVersion 1.2.1 -Force -Scope AllUsers; \
     Install-Module -Name Az.OperationalInsights -RequiredVersion 3.4.0 -Force -Scope AllUsers; \
     Install-Module -Name powershell-yaml        -RequiredVersion 0.4.12 -Force -Scope AllUsers; \
     Install-Module -Name AzLogDcrIngestPS       -RequiredVersion 1.6.2 -Force -Scope AllUsers; \
     Install-Module -Name ImportExcel            -RequiredVersion 7.8.10 -Force -Scope AllUsers"
COPY . /app/
ENTRYPOINT ["pwsh","-NoProfile","-File","/app/container/Start-SIInContainer.ps1"]
```

**Why pinned**: every container in every customer tenant runs the same binary
surface. Drift between Dockerfile and PSGallery latest is the #1 source of
"works locally, breaks in container" bugs.

**Maintenance via `container/Sync-ContainerModules.ps1`** — unattended, scriptable:

```powershell
# Audit only — no writes; prints current pin vs PSGallery latest for each
.\container\Sync-ContainerModules.ps1 -Audit

# Bump only one module (security patch)
.\container\Sync-ContainerModules.ps1 -BumpModule @{ 'ImportExcel' = '7.8.11' } `
                                       -Build -Roll `
                                       -AcrName acrsicont -ResourceGroupName rg-sicontainertest

# Bump everything to latest, rebuild image, roll all caj-si-* jobs (monthly)
.\container\Sync-ContainerModules.ps1 -BumpAll -Build -Roll `
                                       -AcrName acrsicont -ResourceGroupName rg-sicontainertest
```

What the script does, in order:

1. Parse `container/Dockerfile` for `Install-Module -RequiredVersion` lines.
2. Query PSGallery for the latest version of each — print the drift report.
3. (Optional) Apply `-BumpAll` or `-BumpModule` rewrites in place.
4. (Optional) `az acr build` the image with tag `yyyyMMddHHmm` AND `latest`.
5. (Optional) `az containerapp job update --image` on every `caj-si-*` job
   in the RG so they all pick up the new tag.

In-flight job executions finish on the old image; the next trigger pulls the
new one. **No downtime.**

**Drift policy (encoded in the script's help block):**

| Bump type    | Auto-roll OK? | Action                                              |
|--------------|--------------|------------------------------------------------------|
| Patch (z)    | Yes          | `-BumpAll -Build -Roll` directly                     |
| Minor (y)    | After test    | Bump + Build on sicont first, validate, then Roll customer RGs |
| Major (x)    | After test    | Same as minor; expect breaking-change surface       |
| `AzLogDcrIngestPS` | Owner-controlled | Pin to whatever we just shipped; never `BumpAll` blindly — `v1.6.3` has a cert-only-auth gate bug, stay on `1.6.2` until `1.6.4` ships |

**CI hook (optional):** add a weekly scheduled action that runs `-Audit` and
opens an issue if the drift count is non-zero. The repo's GitHub Actions
already has the credentials for ACR; add a job calling the script with
`-Audit` and grepping for `*` rows.

---

## 9b. How to **update the image** (after engine code change)

Two equivalent paths — both server-side via `az acr build`, both zero-downtime:

```powershell
# Path A: full bootstrap (also reconciles cron, env vars, KEDA caps)
cd C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight
.\Bootstrap-ContainerAppJob.ps1

# Path B: image-only roll (faster — skips KEDA/cron reconcile, just rebuilds + rolls)
.\container\Sync-ContainerModules.ps1 -Build -Roll `
    -AcrName acrsicont -ResourceGroupName rg-sicontainertest
```

Path B is the right one when only engine code changed (no Dockerfile / module
bump). Path A is the right one when the change also touches cron, env vars,
KEDA caps, or any param exposed via `$global:SI_Bootstrap_*`.

---

## 9c. How the entrypoint dispatcher works (SI_ROLE)

Every job in the fleet uses the **same** Dockerfile ENTRYPOINT
(`pwsh -NoProfile -File /app/container/Start-SIInContainer.ps1`). The script
branches on `$env:SI_ROLE` at the very top:

| `SI_ROLE`   | What runs                                              | Set by Bootstrap on        |
|-------------|--------------------------------------------------------|----------------------------|
| `worker`    | `Start-SIInContainer.ps1` continues to collection path | `caj-si-<engine>-worker` and legacy `caj-si-<engine>` |
| `producer`  | dispatches to `Invoke-ShardProducer.ps1`              | `caj-si-<engine>-producer` |
| `ra`        | dispatches to `Start-RiskAnalysisInContainer.ps1`      | `caj-si-risk-analysis`     |

**Why not `--command`/`--args`?** The az CLI uses argparse `nargs='+'` for
both, which stops consuming tokens at any leading-dash arg. PowerShell flags
all lead with `-` (`-NoProfile`, `-File`), so `--args -NoProfile -File /app/...`
gets parsed as `--args` (empty) plus unknown globals `-NoProfile -File`. The
SI_ROLE env-var dispatch sidesteps this entirely — same ENTRYPOINT for every
job, different code path inside.

---

## 10. Common issues

| Symptom                                                              | Fix                                                                                       |
|----------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| `Key Vault '<name>' not found`                                       | Pre-create KV before running Setup. § 1.                                                  |
| `New-Guid : The term 'New-Guid' is not recognized`                   | Az SDK's autorest path calls it in a constrained child runspace. Define the shim before any Az cmdlet — see § 3. |
| `az login (interactive) failed`                                      | Container phase requires az CLI signed in. Pre-`az login` or pass SPN secret env vars.    |
| `az acr build` fails with `denied: requested access to the resource is denied` | ACR admin user is disabled. Caller's SPN needs `AcrPush` on the registry.       |
| Worker scale stuck at 0                                              | Queue isn't getting messages — check producer execution log for crash.                    |
| Engine throws `AuthorizationPermissionMismatch` on Storage           | SPN missing `Storage Blob Data Contributor` on `stsicont` (Phase 2 should have granted it). |
| `Required global $global:SI_StorageKey is empty in ...custom.ps1`    | **Engine side (v2.2.314+) doesn't need this** — OAuth-only enforced everywhere on the VM/launcher path. **Container side (Bootstrap-ContainerAppJob.ps1) still injects `--secrets si-storage-key=` for the KEDA queue scaler** because the scaler accepts only key auth (no OAuth scaler path yet). Workaround for now: fetch the key inline before invoking bootstrap — `$global:SI_StorageKey = (Get-AzStorageAccountKey -ResourceGroupName <rg> -Name <sa>)[0].Value`. Container-side OAuth refactor is queued (would require switching to a UAMI-on-CAJ KEDA scaler config). |
| `Required global $global:OpenAI_apiKey is empty in ...custom.ps1`    | Community `Write-SICustomConfig` only emits the KV-pull line, not the 4 OpenAI globals. Workaround: set `$global:OpenAI_endpoint/_deployment/_apiVersion/_apiKey` inline before invoking bootstrap (same shape as `platform-defaults.ps1` lines 1034-1036). Long-term fix: bootstrap should treat OpenAI as optional when `$global:SI_EnableAI` is false. |
| Container App Job execution `Failed` with `-NoProfile -File` not recognised | Old bootstrap put `--command pwsh --args "-NoProfile ..."` per-job. argparse can't pass leading-dash strings as values. Fix: pull new image (SI_ROLE dispatcher landed in v2.3) AND re-run `Bootstrap-ContainerAppJob.ps1` so UPDATE clears stale `command/args`. |
| `caj-si-schema-discovery-*` jobs fail with no orchestrator           | schema-discovery is a stage inside asset-profiling, not a standalone engine. Remove from `$Engines` (bootstrap default does this since the fix) and delete dangling jobs: `az containerapp job delete --name caj-si-schema-discovery-{producer,worker} --resource-group <rg> --yes`. |

---

## 11. Teardown

```powershell
# Stop all auto-runs, keep data
foreach ($e in 'endpoint','identity','azure','schema-discovery','risk-analysis','privilege-tier-classifier','asset-tagging','publicip') {
    az containerapp job update --name "caj-si-$e-producer" --resource-group rg-sicontainertest --cron-expression "" 2>$null
    az containerapp job update --name "caj-si-$e"          --resource-group rg-sicontainertest --cron-expression "" 2>$null
}

# Full delete
Remove-AzResourceGroup -Name rg-sicontainertest -Force
```
