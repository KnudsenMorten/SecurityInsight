<!-- public:start -->

# PlatformMonitoring

Cross-solution **health-check engine** with an email-alert hook. Runs a configurable
battery of checks against a customer's Entra tenant / Azure subscription / Key Vault /
Function App / internet connectivity, aggregates the results, and sends an alert email
on failure. Pairs with any of the solutions published from the same author
(SecurityInsight, PlatformConfiguration, EntraPolicySuite, PIM4EntraPS, ...).

## What it checks (all optional, each individually switchable)

| Toggle | Checks |
| --- | --- |
| `-CheckInternetConnectivity` | HTTP probe to `login.microsoftonline.com`. Catches outbound proxy / firewall issues before other checks fail mysteriously. |
| `-CheckAzureConnectivity` | `Get-AzContext` + `Get-AzSubscription` — confirms the launcher-established SPN / MI can actually talk to ARM. |
| `-CheckGraphConnectivity` | `Connect-MgGraph` + `Get-MgOrganization` — confirms Graph endpoint + minimum read permissions. |
| `-CheckKeyVaultConnectivity` | `Get-AzKeyVaultSecret` on `-KeyVaultName`. Fails if the caller lacks **Secrets User** or if the vault is unreachable. |
| `-CheckFunctionAppAccess` | HTTP GET to `-FunctionAppHealthUrl` expecting 200. Useful if your solution runs in a Function App and you want to detect platform outages. |
| `-CheckSecretExpiry` | Enumerates every Entra app registration in the tenant; flags any whose client secret or certificate expires within `-DaysBeforeExpiry` (default 14) days, or is already expired. |

Each check records a `Passed` / `Failed` result with detail + (if thrown) exception.

## What goes into the alert email

Always includes:

- `TenantId` (to map alerts back to a customer)
- `CustomerName` (free-text label from `$global:CustomerName`)
- Hostname that ran the check
- Timestamp (UTC)
- Totals: passed / failed / checks total
- Per-check `PASS` / `FAIL` block with detail and, if present, exception text

Default recipient is `mok@2linkit.net` — this is the **internal convention** so Morten
can cross-reference alerts against his customer inventory. **Community users must
override** `$global:AlertEmailTo` in their own `LauncherConfig.ps1`.

> Only sends email when at least one check failed. Pass `-AlwaysSendHeartbeat` if you
> want a green "everything's fine" email on every run (useful to catch the check
> script itself silently breaking).

## Typical run

```powershell
cd launchers\Invoke-PlatformHealthCheck
copy LauncherConfig.sample.ps1 LauncherConfig.ps1
notepad LauncherConfig.ps1   # pick auth method + fill in SMTP + CustomerName

.\launcher.community-vm.template.ps1 `
    -CheckInternetConnectivity `
    -CheckAzureConnectivity -CheckGraphConnectivity `
    -CheckKeyVaultConnectivity -KeyVaultName 'kv-securityinsight-prod' `
    -CheckSecretExpiry -DaysBeforeExpiry 21
```

For a scheduled hourly check, drop the above into a Windows scheduled task running
as your service account, or into an Azure Function timer trigger via
`launcher.community-azure.template.ps1`.

## Why this matters

Every SecurityInsight / PlatformConfiguration / etc. deployment depends on a running
SPN secret and working Azure/Graph/KV connectivity. Without a check like this, a
silent secret expiry or a KV RBAC drift means you find out your risk reports have
stopped producing only after weeks — when someone notices the Monday-morning Excel
didn't land in their inbox.

Running this engine every hour on a cheap Function timer (or a scheduled task on an
existing management VM) is the "smoke detector" for every automation solution you
run out of this author's repos.

## Bug reports, PRs, discussions

- **Bugs / feature requests:** [Issues](https://github.com/KnudsenMorten/PlatformMonitoring/issues/new/choose)
- **Questions:** [Discussions](https://github.com/KnudsenMorten/PlatformMonitoring/discussions)
- **PRs:** fork → branch → PR against `main`. Accepted PRs are bridged upstream and
  republished with your commit attribution preserved.

Developed by **Morten Knudsen** — Microsoft MVP (Security, Azure, Security Copilot).
Blog: https://mortenknudsen.net (aka.ms/morten) · GitHub: https://github.com/KnudsenMorten

<!-- public:end -->
