<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/brand/invardia-securityinsight-community-horizontal-reversed.svg">
    <img src="docs/images/brand/invardia-securityinsight-community-horizontal-colour.svg" alt="Invardia SecurityInsight Community edition" width="420">
  </picture>
</p>

# SecurityInsight

**Know which security finding to fix first in your Microsoft estate.**

> ### ⬇️ Download / Install Community — free
> **[Download the latest release](https://github.com/KnudsenMorten/SecurityInsight/releases/latest)** &nbsp;·&nbsp;
> **[Install guide](https://invardia.com/docs/securityinsight/community-scripts/#install)** &nbsp;·&nbsp;
> [Quick start below](#community-quick-start)
>
> Installs into your own Azure subscription with one command. Pro adds more: [Community vs Pro](https://invardia.com/products/securityinsight/).

Microsoft Defender shows you thousands of vulnerabilities, misconfigurations and risky identities, sorted by severity.
An attacker sorts the same list by opportunity: what leads to a domain controller, a Global Administrator or the
tenant itself. When every finding looks equally urgent, your team stays busy and the real risk stays open.

SecurityInsight reads the data you already have in Microsoft Defender, Exposure Graph, Entra ID and Azure. It gives
every device, identity, Azure resource and public IP a Tier 0-3 rating from what it really is and what it can really
do, and it scores every finding by that tier, its severity and the risk factors around it. You get one ranked list of
what to fix first, with the evidence behind every rank.

- **Fix what an attacker would hit first.** The same weakness ranks higher on a domain controller than on a Tier 3
  laptop, and risk factors such as internet exposure or a known exploit raise it further. 138 Risk Analysis reports
  look at your estate the way an attacker does.
- **Tiers from the rights identities really hold.** An identity's tier comes from the Entra roles, API permissions,
  Azure roles and Active Directory groups it holds, including eligible Entra roles, and you see what set it.
- **One object across every source.** Correlation joins the same device, identity or resource across Defender,
  Entra ID and Azure, so each asset has one record with all its properties.
- **Read-only, in your own Azure.** SecurityInsight runs in your own subscription as Azure Container Apps jobs and
  reads Microsoft data as its own managed identity with read-only permissions. It adds no agent to your devices.
- **Your rules, kept.** More than 550 built-in rules classify server roles, applications and appliances. Your own
  rules and settings are kept apart from the built-in ones, so an update never overwrites them.

## Documentation

Everything about SecurityInsight is at **[invardia.com/docs/securityinsight](https://invardia.com/docs/securityinsight/)**:

- [Community edition: the scripts you run](https://invardia.com/docs/securityinsight/community-scripts/)
- [The daily pipeline](https://invardia.com/docs/securityinsight/pipeline/) and [Weighted risk by CMDB service](https://invardia.com/docs/securityinsight/weighted-risk/)
- [Security](https://invardia.com/docs/securityinsight/security/) and [Identities and permissions](https://invardia.com/docs/securityinsight/identities-and-permissions/)
- [Operations](https://invardia.com/docs/securityinsight/operations/), [Guards](https://invardia.com/docs/securityinsight/guards/) and [Data health](https://invardia.com/docs/securityinsight/data-health/)
- [Updates](https://invardia.com/docs/securityinsight/upgrade/), including [SecurityInsight 3 beside 2.2](https://invardia.com/docs/securityinsight/upgrade/#securityinsight-3-beside-22-no-upgrade)

## What you need

- An Azure subscription where SecurityInsight runs as Azure Container Apps jobs, with its own Log Analytics workspace,
  database, storage account and Key Vault. The install creates them.
- To install: Owner on the resource group, or Contributor and Role Based Access Control Administrator on it.
  When the resource group does not exist yet, Owner or Contributor on the subscription.
- Once, for the read-only Microsoft Graph and Defender permissions: a Privileged Role Administrator or Global
  Administrator. Without one, the install finishes and prints the exact command for them.
- Microsoft licenses for the data you want scored: Defender for Endpoint Plan 2 or Defender Vulnerability Management
  for vulnerabilities, Defender Exposure Management for Exposure Graph, Defender for Identity for Active Directory
  data, and Entra ID P2 for identity risk.

## Community quick start

The Community edition installs from this repository into your own Azure subscription. Open
[Azure Cloud Shell](https://shell.azure.com) in PowerShell, signed in to the tenant you want to assess:

```powershell
git clone https://github.com/KnudsenMorten/SecurityInsight.git
cd SecurityInsight

# Your tenant and subscription; every other answer has a default (setup/install-parameters.json lists them all)
@{ installId = 'securityinsight'; tenantId = '<tenant id>'; subscriptionId = '<subscription id>'; location = 'westeurope' } |
    ConvertTo-Json | Set-Content ./config.json

./setup/Install-SecurityInsight.ps1 -ConfigPath ./config.json -PreflightOnly   # checks only, changes nothing
./setup/Install-SecurityInsight.ps1 -ConfigPath ./config.json                  # installs, then runs once
```

The checks run first, and nothing is created until they pass. If a step stops, run the same command with `-Resume`.
You need no PowerShell modules, no Azure CLI and no client secret: the jobs sign in as their own managed identity.
Results arrive as an Excel workbook, a summary mail, Log Analytics tables and the SecurityInsight web app. The full
walk-through is in [Community edition: the scripts you run](https://invardia.com/docs/securityinsight/community-scripts/).

**Updates.** A Community install updates itself from the SecurityInsight update channel. Before anything is
installed, the release is checked against a signed entry: its version, its size and its SHA-256.

**Status reports.** The Community edition sends Invardia an anonymous daily status report: version, hosting type and
run results, with no tenant id, host name or company. Set `$global:SI_Telemetry_Enabled = $false` in your
configuration and nothing is sent.

**Coming from 2.2?** SecurityInsight 3 is installed beside 2.2, not over it. Branch
[`main`](https://github.com/KnudsenMorten/SecurityInsight/tree/main) keeps 2.2 unchanged. Read
[SecurityInsight 3 beside 2.2](https://invardia.com/docs/securityinsight/upgrade/#securityinsight-3-beside-22-no-upgrade).

## Pro editions and support

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/brand/invardia-securityinsight-community-horizontal-reversed.svg">
    <img src="docs/images/brand/invardia-securityinsight-community-horizontal-colour.svg" alt="Invardia SecurityInsight Community edition" width="300">
  </picture>
  &nbsp;&nbsp;&nbsp;
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/brand/invardia-securityinsight-pro-horizontal-reversed.svg">
    <img src="docs/images/brand/invardia-securityinsight-pro-horizontal-colour.svg" alt="Invardia SecurityInsight Pro edition" width="260">
  </picture>
</p>

SecurityInsight Pro (Pro Business and Pro Enterprise) adds the ServiceNow CMDB connector, a CMDB with business
services and its connectors, the vulnerability close-loop to ServiceNow or a SQL table, departments with governance
mails and follow-up tasks, managed updates from Invardia and support from Invardia.

- Product page and editions: [invardia.com/products/securityinsight](https://invardia.com/products/securityinsight/)
- Pricing: [invardia.com/pricing](https://invardia.com/pricing/) · 60-day Pro trial: [invardia.com/trial](https://invardia.com/trial/)
- Pro support: [support@invardia.com](mailto:support@invardia.com) or [portal.invardia.com](https://portal.invardia.com/) > Support
- Questions: [info@invardia.com](mailto:info@invardia.com)
- Community questions and bugs: [GitHub issues](https://github.com/KnudsenMorten/SecurityInsight/issues)

## License

From version 3.0.0, the Community edition is licensed under the [PolyForm Shield License 1.0.0](LICENSE): you may use,
change and run it, also commercially inside your own organization, but not to offer a product that competes with it.
Pro components are not in this repository and need a license from Invardia. Versions published before 3.0.0 stay
under the MIT License they were published with.

Invardia is a brand of 2LINKIT, founded and owned by Morten Knudsen.
