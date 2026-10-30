# Community edition: the scripts you run

SecurityInsight Community is free on GitHub. It is a set of PowerShell scripts that you install and run yourself, in
your own Azure: on a Windows server (Task Scheduler) or as Azure Container Apps jobs. **It has no web app.** Settings
live in configuration files, and results arrive as an Excel workbook, a mail and Log Analytics tables. An Azure Monitor
workbook that you import is the Community dashboard.

This page lists every file in the Community download that you run, one by one: what it is for, how you run it, what it
produces and what it needs. Every script runs on Windows PowerShell 5.1 and PowerShell 7 and needs no PowerShell
modules: Azure, Microsoft Graph and Defender are called over REST.

## How the pieces fit

| Step | What runs | Where the result goes |
|---|---|---|
| Install | A setup script, once | Azure resources, a configuration file |
| Collect | Four profilers and the privilege tier classifier | Log Analytics profile tables |
| Analyse | Risk Analysis (Summary and Detailed) and the risk trend | Log Analytics finding and trend tables |
| Deliver | Risk Analysis | Excel workbook, mail, JSON files, blob storage or a file share |
| Operate | The daily pipeline, the health check, the deviation report | Run health table, console, CSV |
| Update | The update script | A new signed release from GitHub |

On a server, one scheduled task runs the daily pipeline: every step in order, each when the one before it has ended.
In Container Apps, a pipeline job does the same with one job per engine.

## What you need

- An Azure subscription for SecurityInsight's resources: a Log Analytics workspace, a data collection endpoint and
  rules, a storage account and a Key Vault. The setup scripts create them.
- An identity for the scripts. The default is a **managed identity** (of the container jobs, an Azure VM or an Azure
  Arc server), and the setup wizard and the container setup choose it unless you pick otherwise. A service principal
  with a certificate (recommended) or a client secret is a supported choice, and the only one on a server outside
  Azure. It needs read-only rights: Reader on what you want
  profiled, Monitoring Metrics Publisher on the data collection rules, Log Analytics Reader on the workspace, the storage
  data roles on SecurityInsight's own storage account, and read-only Microsoft Graph, Defender XDR and Defender for
  Endpoint application permissions. A grant script makes these grants, or prints them for someone who can.
- Someone who can grant application permissions (Privileged Role Administrator or Global Administrator) and assign
  roles on those scopes, once, during install.
- Optional: an Azure OpenAI deployment (AI tier classification and the AI summary), a Shodan key (public IP exposure),
  an SMTP server (the report mail), a CMDB CSV file (business services and criticality).

## Install

Open [Azure Cloud Shell](https://shell.azure.com) in **PowerShell**, signed in to the tenant you want to assess, and
get the code once:

```powershell
git clone https://github.com/KnudsenMorten/SecurityInsight.git; cd SecurityInsight
```

You sign in as yourself: in Cloud Shell there is no prompt; on your own PC (PowerShell 7 or Windows PowerShell 5.1) a
browser window asks you to sign in. No PowerShell modules, no Azure CLI and no client secret. The checks run first,
and nothing is created until they pass.

**1. The quickest install** (most people start here): one subscription, every other answer has its default (a new
resource group in West Europe, a new Log Analytics workspace, the web app, and the reports mailed to you).

```powershell
./setup/Install-SecurityInsight.ps1 -TenantId <tenant id> -SubscriptionId <subscription id>
```

**2. Your own region, resource group and report recipients**, when you have naming rules or the reports go to a team:

```powershell
./setup/Install-SecurityInsight.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> `
    -Location northeurope -ResourceGroup rg-securityinsight -MailTo secops@contoso.com
```

**3. Read every subscription**, in a management group or in the whole tenant, not only the one SecurityInsight runs in:

```powershell
./setup/Install-SecurityInsight.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> `
    -CollectionScope managementGroup -ManagementGroupId <management group id>      # or -CollectionScope tenantRoot
```

**4. Private network only**: no public endpoints, the web app reachable from your network only. You get the hand-off
list for your network team at the end.

```powershell
./setup/Install-SecurityInsight.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> `
    -PrivateNetwork -VnetAddressPrefix 10.212.24.0/24
```

**5. Check first, or continue an install that stopped:**

```powershell
./setup/Install-SecurityInsight.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -PreflightOnly   # checks only, changes nothing
./setup/Install-SecurityInsight.ps1 -Resume                                                                  # continues with the same answers
```

**Pro trial:** start it at [invardia.com/trial](https://invardia.com/trial/). Your installation page there gives you
the one-line command for the Pro edition, with the same choices as the samples above.

**Every other setting** (your own workspace, SMTP mail, Azure OpenAI, customer-managed keys ...) goes in a
`config.json` keyed as in `setup/install-parameters.json`: `./setup/Install-SecurityInsight.ps1 -ConfigPath ./config.json`.

### The install and configuration scripts

| File | Purpose | How to run it | Produces |
|---|---|---|---|
| `setup\Install-SecurityInsight.ps1` | Guided install as Container Apps jobs. Checks your sign-in, rights, resource providers and names first and changes nothing until they pass; then creates every resource step by step and reports each step. A grant it cannot make ends as a warning with the exact command. Without a licence file it installs Community. | In Azure Cloud Shell: `./setup/Install-SecurityInsight.ps1 -TenantId <tenant id> -SubscriptionId <subscription id>` (the samples above), or `-ConfigPath ./config.json` for every setting. `-PreflightOnly` runs only the checks; `-Resume` continues after a stop. | Resource group, workspace, data collection endpoint and rules, storage, Key Vault, managed identity and its grants, the container registry and image, the Container Apps jobs, a first run and a health check |
| `Setup-SecurityInsight-Unattended.ps1` | A Windows server install without prompts, driven by a JSON file. | `.\Setup-SecurityInsight-Unattended.ps1 -ConfigPath .\setup.json` | Azure resources and `config\SecurityInsight.custom.ps1` |
| `setup\ConfigWizard\Start-SetupWizard.ps1` | A local setup wizard: serves a page on `localhost` only while the script runs and opens it in your browser. You answer tenant, workspace, mail, CMDB, Azure OpenAI and Shodan questions; it sets up the sign-in, creates the Log Analytics resources and writes your configuration file. The sign-in is a **user-assigned managed identity** by default: created, granted and attached to the VM you name (for Container Apps, the jobs' own identity). A service principal with a certificate or a client secret is there when you choose it; on a server outside Azure, where no managed identity can exist, the wizard says so and offers a certificate first, then a secret. It configures the install and nothing else. | `.\setup\ConfigWizard\Start-SetupWizard.ps1`, stop it with Ctrl+C | Managed identity (or a service principal), workspace, data collection endpoint, storage, configuration file |
| `Bootstrap-ContainerAppJob.ps1` | Creates or updates the Container Apps hosting: registry, image built in your registry, Container Apps environment, one job per engine with its schedule, and the pipeline job. The jobs sign in as a user-assigned managed identity by default; a service principal by client secret (`-UseClientSecret`) or by certificate (`-CertificateKeyVaultName` with `-CertificateSecretName`) when you choose it. An install whose configuration already carries a client secret keeps it until you run it with `-UseManagedIdentity`. | `.\Bootstrap-ContainerAppJob.ps1 -ResourceGroupName <rg> -Location <region> -UseManagedIdentity -GrantIdentityRoles` | Container Apps jobs (endpoint, identity, azure, publicip, privilege tier classifier, Risk Analysis Summary and Detailed, trend) |
| `Bootstrap-Storage.ps1` | Creates SecurityInsight's storage account for run state and caches, Entra sign-in only (shared keys off). | `.\Bootstrap-Storage.ps1 -ResourceGroupName <rg> -StorageAccountName <name> -Location <region>` | Storage account, queues and tables |
| `Bootstrap-Auth.ps1` | Service principal installs only: reads the service principal's details and workspace pointers from your Key Vault and writes them into the configuration file. | `.\Bootstrap-Auth.ps1 -KeyVaultName <vault>` | Configuration entries |
| `setup\Grant-SIIdentity.ps1` | Grants a managed identity (VM, Arc server or user-assigned), or with `-AppId <client id>` an app registration that signs in with a certificate, everything SecurityInsight reads with. Prints what is present and missing; changes nothing without `-Apply`. `-Tagging` grants the separate write plan for asset tagging's own identity. | `.\setup\Grant-SIIdentity.ps1 -VmName <vm> -VmResourceGroup <rg> -KeyVaultName <vault> -Apply` | Role assignments and application permissions |
| `setup\Validate-SILogAnalytics.ps1` | Creates or checks the workspace, data collection endpoint, rules and tables. | `.\setup\Validate-SILogAnalytics.ps1` | Log Analytics resources |
| `setup\Validate-SIOpenAI.ps1` | Creates or checks an Azure OpenAI account and model deployment for the AI features. | `.\setup\Validate-SIOpenAI.ps1 -SubscriptionId <sub> -ResourceGroupName <rg> -Location <region>` (`-ValidateOnly` to check) | Azure OpenAI account and deployment |
| `setup\Install-SIFlowTask.ps1` | Server install: runs the engines as one daily pipeline (one scheduled task) instead of one task per engine. Previewed, reversible with `-Remove`. | `.\setup\Install-SIFlowTask.ps1 -Apply` (as administrator) | Scheduled task, the old per-engine tasks disabled |
| `setup\Switch-SIJobOrchestration.ps1` | Container install: switch between the daily pipeline and one timer per job. Previewed, reversible. | `.\setup\Switch-SIJobOrchestration.ps1 -Mode flow -ResourceGroupName <rg> -Apply` | Job triggers changed |
| `setup\Set-SIStorageSharedKey.ps1` | Shows, or turns off, shared-key access on SecurityInsight's storage account after proving nothing uses a key. | `.\setup\Set-SIStorageSharedKey.ps1 -Disable` | Storage setting |

**One script on its own.** The configuration scripts above that act on Azure and Entra (`Grant-SIIdentity`,
`Validate-SIOpenAI`, `Set-SIStorageSharedKey`, `Switch-SIJobOrchestration`,
`Set-SISqlAdminGroup`, `Grant-SISupportAccess`) and the health checks `Test-SIInstall` and `Invoke-SIJobsOnce` are also
published one by one, each as a single self-contained file that needs no PowerShell module and no download of the
release, for a machine without the install or for Azure Cloud Shell:

```powershell
Invoke-WebRequest https://invardia.com/support/si/Grant-SIIdentity.ps1 -OutFile Grant-SIIdentity.ps1
.\Grant-SIIdentity.ps1 -VmName <vm> -VmResourceGroup <rg> -KeyVaultName <vault>
```

Any of them: `https://invardia.com/support/si/<Script>.ps1`; the checksums are in `SHA256SUMS.txt` next to them. Run on
its own, a script does not read an install's configuration file unless you name it with `-ConfigPath`.

**Configuration files** (edit, do not run): `config\SecurityInsight.custom.community.sample.ps1` (copy to
`SecurityInsight.custom.ps1`), `config\SecurityInsight.custom.reference.ps1` (every setting with a generated glossary:
purpose, real default, effect, when to change it) and `launcher\<engine>\LauncherConfig.custom.sample.ps1` per engine.
Your `*.custom.*` files are never touched by an update.

## Collect: the profilers

On a server you run the `launcher.community-vm.ps1` of each engine (scheduled by the pipeline task, or by hand). In
Container Apps the same engines run as jobs through `container\Start-SIInContainer.ps1`. Collection is read-only.

| File | Purpose | How to run it | Produces |
|---|---|---|---|
| `launcher\endpoint\launcher.community-vm.ps1` | Profiles every device from Defender XDR and Exposure Graph: server roles from installed software and detection rules, tier from rules and from the most-privileged users who log on, Defender for Cloud recommendations. | `.\launcher\endpoint\launcher.community-vm.ps1` (`-ForceFullRun` ignores the change cache; `-WhatIfMode` stops before writing) | `SI_Endpoint_Profile_CL`, run health |
| `launcher\identity\launcher.community-vm.ps1` | Profiles users, groups and service principals from Entra ID and Defender for Identity: tier from the roles and permissions each one holds, including nested group chains; MFA, SSPR and passwordless registration. | `.\launcher\identity\launcher.community-vm.ps1` | `SI_Identity_Profile_CL`, run health |
| `launcher\azure\launcher.community-vm.ps1` | Profiles Azure resources from Azure Resource Graph, with tags inherited from resource group, subscription and management group. | `.\launcher\azure\launcher.community-vm.ps1` | `SI_Azure_Profile_CL`, run health |
| `launcher\publicip\launcher.community-vm.ps1` | Profiles the public IPs of devices and Azure resources, linked to the asset behind each one; with a Shodan key adds open ports, services, certificates and CVEs. Runs after endpoint and Azure. | `.\launcher\publicip\launcher.community-vm.ps1` | `SI_PublicIP_Profile_CL`, run health |
| `launcher\privilege-tier-classifier\launcher.community-vm.ps1` | Refreshes the privilege tier catalog (Entra roles, API permissions, Azure roles, AD groups) with your own Azure OpenAI. Optional: without Azure OpenAI the shipped catalog is used. | `.\launcher\privilege-tier-classifier\launcher.community-vm.ps1` | The tier catalog file the profilers read |
| `asset-profiling-providers\generic-cmdb\Refresh-CmdbCache.ps1` | Loads your CMDB CSV file (business services, criticality, data sensitivity, owners, CIs) into SecurityInsight's storage, where the profilers and Risk Analysis read it. The CSV can come from any CMDB or be kept by hand. | `.\asset-profiling-providers\generic-cmdb\Refresh-CmdbCache.ps1 -StorageAccountName <name> -CsvPath .\CMDB.csv` | CMDB tables in storage |

## Analyse and deliver

| File | Purpose | How to run it | Produces |
|---|---|---|---|
| `launcher\risk-analysis\launcher.community-vm.ps1` | Risk Analysis: runs the report catalog against the profiles and Defender, scores every finding (consequence x asset tier x risk factors, weighted by CMDB criticality) and ranks it, most critical asset first. Summary and Detailed are two runs. | `.\launcher\risk-analysis\launcher.community-vm.ps1 -Summary` and `-Detailed`; `-ReportTemplate <name>` picks a report set; `-BuildSummaryByAI` adds the AI summary | Excel workbook (no Office needed), summary mail, `SI_RiskAnalysis_Summary_CL` and `SI_RiskAnalysis_Detailed_CL`, JSON files, optional upload to blob storage or a file share, today's trend row |
| `launcher\asset-trend\launcher.community-vm.ps1` | The daily risk trend: one point per day overall, per tier, per security domain and per severity. | `.\launcher\asset-trend\launcher.community-vm.ps1` (`-Grain week -Weeks 12 -ShowWeeklyRate` prints a weekly rate) | `SI_Trend_CL`, console |
| `preview\AzureWorkbook\SecurityInsight-RiskAnalysis.workbook.json` | The Community dashboard: an Azure Monitor workbook over the SecurityInsight tables (risk score tiles, trend, domain and tier charts, top N, identity inventory). | Import it once: Azure Monitor, Workbooks, Advanced Editor, paste, save | A workbook in your Azure portal |

Reports, exclusions, risk weights and the scoring matrix are files: `RiskAnalysis_Queries_Custom.yaml`,
`RiskAnalysisGlobalExclusions.custom.json`, `<Report>.exclude.custom.json` and `riskscore_weighted.schema.custom.json`.

## Act and operate

| File | Purpose | How to run it | Produces |
|---|---|---|---|
| `launcher\asset-tagging\launcher.community-vm.ps1` | Writes SecurityInsight's classification back as Defender machine tags, Azure resource tags and Entra custom security attributes, from tagging rules. **Report only by default**: a run logs every tag it would set and changes nothing. It writes only when you ask: `-Apply` on a run, or `$global:SI_AssetTagging_Apply = $true` in your configuration. The one script that can write to your tenant; its identity needs the write rights (`setup\Grant-SIIdentity.ps1 -Tagging`). An install that wrote tags with an earlier version is told once, on its first run after the update, that tagging is now report only and how to switch writing back on. | `.\launcher\asset-tagging\launcher.community-vm.ps1` (report only), then with `-Apply` to write. `-WhatIfMode` still works and means report only. | `SI_AssetTagActivity_CL`; tags only when writing is on |
| `setup\Get-SIDeviationReport.ps1` | Every deviation from the shipped defaults: changed settings, exclusions, disabled detections, tier moves, overridden reports and risk weights, with who changed them and when. Reads your custom files; writes nothing to the install. | `.\setup\Get-SIDeviationReport.ps1 -AsCsv` | Console or a CSV file |
| `engine\flow\Invoke-SIJobFlowRun.ps1` | The daily pipeline runner, started by the scheduled task or the pipeline job. You can also start one step or the rest of a run by hand. | `.\engine\flow\Invoke-SIJobFlowRun.ps1 -HostKind Vm -Step <step>` or `-FromStep <step>` | Each step run in order, run health per step |
| `diagnostics\Test-SIInstall.ps1` | Read-only health check: rows and last time per SecurityInsight table, how each engine's last run ended, the data collection rules, and that the install's identity holds no write role outside its own resource group. Exit code 1 when anything is wrong. | `.\diagnostics\Test-SIInstall.ps1` | Console report |
| `diagnostics\Invoke-SIJobsOnce.ps1` | Runs every Container Apps job of the install once, in pipeline order, and reports each run. | `.\diagnostics\Invoke-SIJobsOnce.ps1 -ResourceGroup <rg>` (`-PlanOnly` shows the order) | Job runs, console report |
| `tools\Run-AllEngines.ps1` | First run or demo on a server: starts every launcher in its own window, or one after the other. | `.\tools\Run-AllEngines.ps1 -Sequential` | The engines' normal output |

## Update

| File | Purpose | How to run it | Produces |
|---|---|---|---|
| `Update-SecurityInsight.ps1` | Takes the release your update ring approves from SecurityInsight's signed update channel on GitHub. It checks the signature, the product, the ring and that the version is not older, checks the download's size and SHA-256, pauses the scheduled tasks, keeps a backup and restores it on any failure. Ring 3 (broad) is the default; ring 2 is early release. | `.\Update-SecurityInsight.ps1` (schedule it, or run it when you choose; `-ShowReleaseNotes` prints what changed) | The new release in place; your custom files, logs and output untouched |
| `setup\Invoke-SIContainerUpdate.ps1` | Container install: after an update, rebuilds the engine image in your own registry, rolls the jobs, verifies them and rolls back on failure. `Update-SecurityInsight.ps1` calls it for you. | `.\setup\Invoke-SIContainerUpdate.ps1 -Apply` | A new image and updated jobs |

Community has no automatic update job: you run or schedule the update script.

## Container entry points

You do not run these yourself; the Container Apps jobs start them. `container\Start-SIInContainer.ps1` runs one engine
from the job's settings, `container\Start-RiskAnalysisInContainer.ps1` runs a Risk Analysis job, and
`container\Invoke-ShardProducer.ps1` splits a large tenant's collection into parts that several replicas work through
(optional queue scaling).

## Files that ship but are not for Community use

| File | Why it is there |
|---|---|
| `setup\Upgrade-SIToPro.ps1`, `setup\Install-SIUpdaterJob.ps1`, `container\updater\Start-SIUpdater.ps1` | The automatic updater for Pro installs. Its update client ships only in the Pro package, so in Community it has nothing to update from. |
| `engine\asset-tagging\Invoke-SIAssetTaggingJob.ps1` | Asset tagging as a container job (caj-si-asset-tagging), in the Community edition and Pro alike; it only reports until its writes are granted and switched on. |
| `setup\Set-SISqlAdminGroup.ps1`, `setup\Grant-SISupportAccess.ps1` | The Pro database's admin group, and access for the Invardia Support app, which is part of a Pro agreement. |
| `launcher\<engine>\launcher.internal-vm.ps1` | Launchers for an internal automation framework; Community uses `launcher.community-vm.ps1`. |
| `tools\Push-PreviewBundle.ps1`, `tools\Validate-PublishYml.ps1`, `demo\Install-DemoConfig.ps1`, the schema and query documentation tools and the measuring scripts in `diagnostics\` | Tools the SecurityInsight team uses to publish releases, build documentation and measure engine changes. |

## What Community does not include

These are in the Pro editions only, and their code is not in the Community download:

- The **management web app**: wall board, risk score and management views, collection views, findings workspace, tier
  board, CMDB and service map, settings with Review & commit and change history, the deviation page, Ask
  SecurityInsight and the MCP server.
- The **Pro database**: every collection with its assets and findings, daily aggregates and retention.
- **Cross-source correlation**: one configuration item per asset across every source, with durable ids.
- **Connectors**: ServiceNow (CMDB and vulnerabilities), a SQL table or any REST system, and the **vulnerability
  close-loop** with its guards and daily mail.
- **Governance**: exemptions with approval and review, departments, external advisors, roles and scopes.
- **Template releases** by update ring with roll back, the **signed licence**, **automatic signed updates** through
  Invardia, and **support** through an app you control.

Community sends anonymous status reports to Invardia, once a day and at the end of each engine run (version, edition,
hosting, how the run ended and counts in ranges; no tenant, no host name, no error text). It is on by default; turn it
off with `$global:SI_Telemetry_Enabled = $false` in your configuration file.

Questions: info@invardia.com.
