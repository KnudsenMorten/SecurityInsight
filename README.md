# SecurityInsight

SecurityInsight is a **risk-based prioritization add-on for Microsoft Defender**. It replaces the traditional Secure Score model with a scoring system built on **consequence, probability, and contextual risk factors** — giving security teams a clear, ordered list of what to fix first.

> **The core idea is simple: take the first line in the Excel output. It has the highest risk score. Work your way down.**

My customers value SecurityInsight because it lets them make better remediation decisions by combining **asset criticality** with **real-world exploitability context** — rather than treating every finding as equally urgent.

---

## 📺 Video Walkthroughs

| Topic | Link |
|---|---|
| Summary Excel output | [Watch](https://youtu.be/Txno9r2pJj4) |
| Summary AI output mail | [Watch](https://youtu.be/kFhrkB0KHvg) |
| Detailed Excel output | [Watch](https://youtu.be/kDrWDzOuWos) |
| Collect/Build Risk Analytics (Summary) | [Watch](https://youtu.be/taW7k4uY9Qo) |
| RiskAnalytics RiskIndex | [Watch](https://youtu.be/YzPIUqU9vJU) |
| RiskAnalytics Queries Locked YAML file | [Watch](https://youtu.be/OImndAACTy0) |
| Run Tagging | [Watch](https://youtu.be/erIS68DaaB8) |
| Tagging Custom YAML file | [Watch](https://youtu.be/_WzIVRe0YxU) |
| Tagging Locked YAML file | [Watch](https://youtu.be/ndTiLZzcl58) |

---

## 📑 Table of Contents

- [Executive Summary](#executive-summary)
  - [🧩 What it is](#-what-it-is)
  - [🚨 Problem it solves](#-problem-it-solves)
  - [⚙️ How it works](#️-how-it-works)
    - [🔢 Risk model](#-risk-model)
    - [🏷️ Critical asset tagging](#️-critical-asset-tagging)
    - [🕸️ Graph-based analysis](#️-graph-based-analysis)
    - [🧮 Risk analysis engine](#-risk-analysis-engine)
    - [📊 Reporting](#-reporting)
  - [💡 Key idea](#-key-idea)

---

### 🔍 Core Concepts

- [The Challenge: Too Many Security Recommendations](#the-challenge-too-many-security-recommendations)
- [A Risk-Based Prioritization Model](#a-risk-based-prioritization-model)
- [Why We Use a Graph — Understanding Exposure Graph Architecture](#why-we-use-a-graph--understanding-exposure-graph-architecture)
- [Example of an Attack Path](#example-of-an-attack-path)
- [Why Graph Architecture Matters](#why-graph-architecture-matters)

---

### 📊 Risk Model & Scoring

- [Risk Score Model](#risk-score-model)
  - [Severity Prioritization \| Risk Score Definitions](#severity-prioritization--risk-score-definitions)
  - [Criticality Prioritization \| Risk Score Definitions](#criticality-prioritization--risk-score-definitions)
- [Risk Index - How we prioritize scoring (customizable)?](#risk-index---how-we-prioritize-scoring-customizable)

---

### 🏷️ Asset Criticality & Classification

- [Asset Criticality Classification](#asset-criticality-classification)
  - [Identity Asset Criticality Classification](#identity-asset-criticality-classification)
    - [Active Directory — Built-in Groups](#active-directory--built-in-groups)
    - [Active Directory — Permissions](#active-directory--permissions)
    - [Entra ID — Built-in Roles](#entra-id--built-in-roles)
    - [Entra ID — API Permissions](#entra-id--api-permissions)
    - [Azure — Built-in Roles](#azure--built-in-roles)
    - [Azure — Permissions](#azure--permissions)
    - [Accounts](#accounts)
  - [Endpoint / Device Asset Criticality Classification](#endpoint--device-asset-criticality-classification)
    - [Server Roles](#server-roles)
    - [Management](#management)
    - [Infrastructure](#infrastructure)
    - [Hypervisor](#hypervisor)
    - [Network Equipment](#network-equipment)
    - [IoT / OT](#iot--ot)
    - [Client Devices](#client-devices)
  - [Cloud (Azure) Asset Criticality Classification](#cloud-azure-asset-criticality-classification)
    - [Compute](#compute)
    - [Storage](#storage)
    - [Identity & Access](#identity--access)
    - [Networking](#networking)
    - [Management & Governance](#management--governance)
    - [Hypervisor / Fabric](#hypervisor--fabric)

---

### 📈 Reporting & Outputs

- [Reporting](#reporting)

---

### 🏛️ Governance & Alignment

- [Governance and Compliance](#governance-and-compliance)
  - [NIS2 Directive](#nis2-directive)
  - [CIS Critical Security Controls](#cis-critical-security-controls)

---

### ⚙️ Operational Value

- [Operational Benefits](#operational-benefits)
- [Future Opportunities](#future-opportunities)
- [Transparency and Flexibility](#transparency-and-flexibility)
- [Collaboration with Microsoft](#collaboration-with-microsoft)

---

### 🗂️ Solution Structure

- [Files Overview](#files-overview)
  - [Asset Tagging](#asset-tagging)
  - [Asset Tagging Maintenance - Clean-up/Remove orphaned tags](#asset-tagging-maintenance---clean-upremove-orphaned-tags)
  - [Risk Analysis](#risk-analysis)
  - [Support file](#support-file)
  - [Sample Output files](#sample-output-files)

---

### 🚀 Implementation Guide

- [High-level Overview of Implementation](#high-level-overview-of-implementation)

#### Step 1: Prepare SecurityInsight files
- [Step 1: Prepare SecurityInsight files on automation-server](#step-1-prepare-securityinsight-files-on-automation-server)
  - [1.1 Download files](#11-download-all-files-from-github-site-and-create-folder-on-automationbatch-server)
  - [1.2 Install PowerShell modules](#12-install-necessary-powershell-modules-on-server-optional-as-the-script-will-also-do-this-if-missing)

#### Step 2: Entra App onboarding
- [Step 2: Onboarding of Entra App registration](#step-2-onboarding-of-entra-app-registration---to-be-used-with-securityinsight)
  - [2.1 Create App Registration](#21-create-entra-app-registration-spn-and-set-secret-note-it-down)
  - [2.2 API permissions](#22-delegate-api-permissions-to-entra-app-spn)
  - [2.3 Azure permissions](#23-delegate-tag-contributor-permissions-in-azure-to-entra-app-spn-on-tenant-root-level-to-ensure-the-possibility-to-tag-all-azure-resources)

#### Step 3: Asset tagging
- [Step 3: Setting Asset Tier Level using tagging](#step-3-setting-asset-tier-level-using-tagging)
  - [Structure of query in YAML-file](#structure-of-query-in-yaml-file)
  - [Asset Tagging files](#asset-tagging-files)
  - [3.1 Adjust authentication](#step-31-adjust-the-authentication-details-in-launcher-file-runcriticalassettaggingps1-spntenantid-spnclientid-spnclientsecret)
  - [3.2 WhatIf mode](#step-32-adjust-the-whatifmode-to-true-if-you-are-only-testing-otherwise-leave-it-as-false-to-set-the-tags)
  - [3.3 Run tagging (PROD)](#step-33-prod-run-critical-asset-launcher-to-tag-recommended-tags-in-prod-mode)
  - [3.4 Schedule recurring job](#step-34-prod-setup-recurring-job-to-run-every-x-hours-using-task-scheduler-or-3rd-party-software-like-visualcron)
  - [3.5 Adjust queries (TEST)](#step-35-test-adjust-custom-yaml-file-to-tag-resources-in-test-mode)
  - [3.6 Run tagging (TEST)](#step-36-test-run-critical-asset-launcher-to-tag-recommended-tags-in-test-mode)
  - [3.7 Promote to PROD](#step-37-prod-adjust-queries-to-prod-mode-once-happy-now-they-will-be-included-in-the-recurring-job)

#### Step 4: Criticality classification
- [Step 4: Setting Asset Criticality Level Classification](#step-4-setting-asset-criticality-level-classification)
  - [4.1 Azure resources](#step-41---how-to-setup-criticality-tier-level-against-azure-resources)
  - [4.2 Defender devices](#step-42---how-to-setup-criticality-tier-level-against-defender-device-resources)
  - [Gaps / Missing capabilities](#what-am-i-missing-in-critical-asset-management)

#### Step 5: Risk analysis
- [Step 5: Run the Risk Analysis](#step-5-run-the-risk-analysis)
  - [Files Overview (Risk Analysis)](#files-overview-risk-analysis)
  - [5.1 Authentication & SMTP](#step-51-adjust-the-authentication--smtp-details-in-launcher-file-runsecurityinsightps1)
  - [5.2 Run analysis (Summary & Detailed)](#step-52a-run-risk-analysis-launcher-in-summary-mode-cmdline)
  - [5.3 AI integration](#step-53a-deploy-openai-instance-to-enable-ai-support-deploy_openai_payg_instance_securityinsightsps1)

------

# 📦 Installation & Running

> **Start here if you are installing SecurityInsight for the first time.** Everything below is
> the v2 layout — one launcher per engine, customer credentials in a `LauncherConfig.ps1` file
> (never in code), data files split between platform-locked and customer-editable.

## Repository layout

Once you have the files on disk, the tree looks like this:

```
SecurityInsight/
├── scripts/                                              ← engine scripts (don't edit)
│   ├── Build_Tier_Definitions_JSON_File.ps1
│   ├── CriticalAssetTagging.ps1
│   ├── CriticalAssetTaggingMaintenance.ps1
│   ├── CriticalAssetTaggingMaintenance_FixConflictingTags.ps1
│   ├── Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1
│   ├── IdentityAssetsCollectDefineTierIngestLog.ps1
│   ├── Onboarding_IdentityAssets_LogAnalytics.ps1
│   ├── SecurityInsight_RiskAnalysis.ps1
│   └── UpdateSecurityInsight.ps1
├── launchers/                                            ← one folder per engine
│   ├── CriticalAssetTagging/
│   │   ├── launcher.manifest.json
│   │   ├── launcher.community-vm.template.ps1              ← run this on a Windows box / dev PC
│   │   ├── launcher.community-azure.template.ps1           ← run this from a Function / Logic App / Hybrid Worker
│   │   └── LauncherConfig.sample.ps1                       ← copy to LauncherConfig.ps1, then edit
│   ├── (one folder for every other engine, same shape)
│   └── ...
├── data/                                                 ← YAML / CSV / JSON the engines read
│   ├── SecurityInsight_CriticalAssetTagging_Locked.yaml    ← platform-curated (overwritten on update)
│   ├── SecurityInsight_CriticalAssetTagging_Custom.yaml    ← stripped starter — YOU edit this
│   ├── SecurityInsight_RiskAnalysis_Queries_Locked.yaml    ← platform-curated
│   ├── SecurityInsight_RiskAnalysis_Queries_Custom.yaml    ← stripped starter — YOU edit this
│   ├── SecurityInsight_RiskIndex.csv                       ← customer-TUNABLE (preserved on update)
│   ├── SecurityInsight_IdentityTiering.json                ← customer-TUNABLE (preserved on update)
│   └── _samples/                                           ← full reference copies (overwritten on update)
│       ├── SecurityInsight_CriticalAssetTagging_Custom.yaml  ← complete sample for the custom tagging file
│       ├── SecurityInsight_RiskAnalysis_Queries_Custom.yaml  ← complete sample for the custom queries file
│       ├── Sample - RiskAnalysis_Summary_Bucket.xlsx         ← what a Summary report looks like
│       ├── Sample - RiskAnalysis_Detailed_Bucket.xlsx        ← what a Detailed report looks like
│       └── Sample mail - Summary / Detailed report.pdf       ← what the AI summary email looks like
├── docs/                                                 ← all documentation, images, Visio, Word/PDF
├── CONTRIBUTING.md                                       ← PR flow
├── LICENSE                                               ← MIT
├── RELEASENOTES.md                                       ← auto-generated per release
└── README.md                                             ← this file
```

## File update rules (important)

When a new release is published you can refresh your local copy with `git pull`, with
`UpdateSecurityInsight.ps1`, or by re-downloading the release zip. The rules are always:

| Path | On update | Why |
| --- | --- | --- |
| `scripts/*.ps1` | **Overwritten** | Platform ships these; you should never edit them. |
| `data/*_Locked.*` | **Overwritten** | Platform-curated recommended content. |
| `data/_samples/*` | **Overwritten** | Reference material, always fresh. |
| `data/*_Custom.*` | **Preserved** (install-once) | Your tagging + query customisations stay. |
| `data/*.csv`, `data/*.json` (no suffix) | **Preserved** (install-once) | Customer-tunable defaults (e.g. `SecurityInsight_RiskIndex.csv`, `SecurityInsight_IdentityTiering.json`) — your edits stay. |
| `launchers/<Engine>/launcher.*.template.ps1` | **Overwritten** | Template code. |
| `launchers/<Engine>/launcher.manifest.json` | **Overwritten** | Launcher metadata. |
| `launchers/<Engine>/LauncherConfig.sample.ps1` | **Overwritten** | Sample tracked in repo. |
| `launchers/<Engine>/LauncherConfig.ps1` | **NEVER in the repo** (`.gitignore`'d) | Your credentials stay on your machine. |
| `docs/*` | **Overwritten** | Documentation. |

> **Rule of thumb:** anything with `_Locked` in the name is ours. Anything with `_Custom` in
> the name, or a bare `.csv` / `.json` in `data/`, or `LauncherConfig.ps1` — is yours. Edit
> freely, it survives every update.

## Running — quick start

The walkthrough below takes a first-time user from zero to a working Summary report. It
assumes PowerShell 7+ on a Windows box (the v1 engines also run on Windows PowerShell 5.1).

### Step 1 — Get the files

Pick either:

**Option A — Download the release zip** (recommended for non-developers):

1. Go to the [Releases page](https://github.com/KnudsenMorten/SecurityInsight/releases/latest).
2. Under **Assets**, download `SecurityInsight-vX.Y.Z.zip`.
3. Extract anywhere, e.g. `C:\SecurityInsight\`.

**Option B — Clone with git** (recommended for developers — makes updates a `git pull`):

```powershell
git clone https://github.com/KnudsenMorten/SecurityInsight.git C:\SecurityInsight
cd C:\SecurityInsight
```

(Tip: for early-access features, add `-b preview`.)

### Step 2 — Create your Entra App registration (Service Principal)

SecurityInsight needs its own Entra App (SPN) with read access to Defender + ARG. Full step-by-step
with screenshots is in [Step 2 of the Implementation Guide below](#step-2-onboarding-of-entra-app-registration---to-be-used-with-securityinsight). Short version:

1. **Entra portal → Identity → Applications → App registrations → New registration.** Name it
   `SecurityInsight-SPN`, single-tenant, no redirect URI.
2. **Overview tab** → copy the **Application (client) ID** and the **Directory (tenant) ID**.
3. **Certificates & secrets → Client secrets → New client secret.** Copy the value immediately.
4. **API permissions → Add a permission → APIs my organization uses**, then add these three
   (all three require **Admin Consent** after adding):
   - `Microsoft Threat Protection` → `AdvancedHunting.Read.All`
   - `Microsoft Graph`             → `ThreatHunting.Read.All`
   - `WindowsDefenderATP`          → `Machine.ReadWrite.All`
5. **Azure RBAC** — on the target subscription(s) or management group, grant the SPN:
   - `Reader` for read-only queries.
   - `Tag Contributor` so the tagging engine can set tags. (Use management group scope to cover
     all subscriptions at once.)

After this step you should have: **tenant id**, **client id**, and **client secret** (the raw
value, not the secret id).

### Step 3 — Create your `LauncherConfig.ps1`

Every launcher folder ships a `LauncherConfig.sample.ps1`. Copy it and fill in the three
values you just got:

```powershell
cd C:\SecurityInsight\launchers\SecurityInsight_RiskAnalysis
copy LauncherConfig.sample.ps1 LauncherConfig.ps1
notepad LauncherConfig.ps1
```

Inside `LauncherConfig.ps1`:

```powershell
$global:SpnTenantId     = '<your-tenant-id>'
$global:SpnClientId     = '<your-app-client-id>'
$global:SpnClientSecret = '<your-client-secret-value>'

# optional extras for scheduled runs:
# $global:ReportTemplate_Default = 'RiskAnalysis_Summary_Bucket'
# $global:SendMail               = $false
```

`LauncherConfig.ps1` is `.gitignore`'d and never overwritten by any update mechanism — it's
yours, forever.

> **Repeat Step 3 for each engine you plan to use.** Every launcher folder has its own
> `LauncherConfig.sample.ps1`. For solutions that use the same SPN across every launcher,
> see the "master config" pattern in [community-testing-guide.md](docs/community-testing-guide.md).

### Step 4 — Run the launcher

Run the community launcher for the engine you want. For a Summary risk analysis:

```powershell
cd C:\SecurityInsight\launchers\SecurityInsight_RiskAnalysis
.\launcher.community-vm.template.ps1 -Summary
```

First run will auto-install any missing PowerShell modules (`Az`, `Microsoft.Graph`,
`MicrosoftGraphPS`, `ImportExcel`, `powershell-yaml`). Subsequent runs only load them.

Same shape for the other engines:

```powershell
# Apply SecurityInsight tier tags across Defender + Azure
cd C:\SecurityInsight\launchers\CriticalAssetTagging
.\launcher.community-vm.template.ps1 -Scope PROD

# Identity-asset inventory + tier assignment
cd C:\SecurityInsight\launchers\IdentityAssetsCollectDefineTierIngestLog
.\launcher.community-vm.template.ps1
```

### Step 5 — (Cloud-hosted alternative) run from an Azure Function or Logic App

If you don't want a Windows VM, you can host SecurityInsight in **Azure Functions** (PowerShell 7.4
runtime) or trigger it from a **Logic App** / **Hybrid Runbook Worker**. The `-azure`
launcher flavour is designed exactly for this — no credentials on disk, secret comes from
Key Vault via a **Managed Identity** (MI).

> **There is currently no provisioning script** that creates the Function App / Logic App
> for you. You set the infra up once by hand (or via your existing IaC), then deploy the
> SecurityInsight code on top. An opinionated provisioner (`Onboarding_SecurityInsight_Hosting.ps1`)
> is on the roadmap — watch the [Discussions](https://github.com/KnudsenMorten/SecurityInsight/discussions)
> for progress.

#### 5.1 Provision the Azure resources (one-time)

Create the following (portal / Bicep / Terraform — your choice):

1. **Resource group** to hold everything (e.g. `rg-securityinsight-host`).
2. **Storage account** — required backing store for the Function App. Standard LRS is fine.
3. **Azure Function App**:
   - **Runtime:** PowerShell 7.4.
   - **Hosting plan:** Consumption or Premium (Consumption is cheapest; Premium if you need VNet
     integration or always-on).
   - **System-assigned Managed Identity:** **enabled**.
4. **Azure Key Vault** in the same tenant (can be an existing one).
   - Secrets to add:
     - `Modern-ApplicationId-Azure` — the SPN's Application (client) ID.
     - `Modern-Secret-Azure` — the SPN's client secret value.
     - (optional) `Modern-CertificateThumbprint-Azure` — only if you're using cert auth
       instead of secret. Leave blank otherwise.
5. **RBAC on the Key Vault**: grant the Function App's system-assigned MI the
   **Key Vault Secrets User** role on the Key Vault's access-policy or RBAC scope.
6. **SPN permissions** (same as Step 2 for the VM flow) — the SPN whose secret you stored
   in Key Vault needs the Defender / Graph / Azure permissions listed there.

#### 5.2 Deploy SecurityInsight code into the Function App

Simplest shape: a single HTTP-triggered (or timer-triggered) function whose body invokes
the community-azure launcher. Conceptual layout inside the Function App:

```
wwwroot/
├── host.json
├── profile.ps1
├── requirements.psd1                       ← lists Az, Microsoft.Graph, MicrosoftGraphPS, ImportExcel, powershell-yaml
├── scripts/                                ← copied verbatim from the SecurityInsight repo
├── launchers/
│   └── SecurityInsight_RiskAnalysis/
│       └── launcher.community-azure.template.ps1
└── SecurityInsight_RiskAnalysis_Fn/
    ├── function.json                       ← timer / HTTP trigger binding
    └── run.ps1                             ← one-liner that dot-sources the launcher
```

`SecurityInsight_RiskAnalysis_Fn/run.ps1`:

```powershell
param($Timer)
$launcher = Join-Path $env:HOME 'site\wwwroot\launchers\SecurityInsight_RiskAnalysis\launcher.community-azure.template.ps1'
& $launcher
```

Deploy via your preferred path — `func azure functionapp publish`, GitHub Actions
`Azure/functions-action`, or zip-deploy via Portal.

#### 5.3 Configure Function App settings

In the Function App → **Configuration → Application settings**, add:

| App setting | Value | Notes |
| --- | --- | --- |
| `AUTOMATEIT_TENANT_ID` | `<your-tenant-id>` | Same SPN tenant as the secrets in Key Vault. |
| `AUTOMATEIT_SUBSCRIPTION_ID` | `<subscription to query>` | Used by Az cmdlets for scope. |
| `AUTOMATEIT_KEYVAULT` | `<kv-name>` | Short name, not full URI. |
| `AUTOMATEIT_STORAGE_ACCOUNT` | `<optional>` | Only if the engine writes state to Azure Table. |

The `launcher.community-azure.template.ps1` reads those env vars, calls
`New-PlatformContext`, resolves the SPN secret via MI → Key Vault, and invokes the engine.

#### 5.4 Trigger + schedule

For timer trigger (run every 4 hours):

```json
// SecurityInsight_RiskAnalysis_Fn/function.json
{
  "bindings": [
    {
      "name": "Timer",
      "type": "timerTrigger",
      "direction": "in",
      "schedule": "0 0 */4 * * *"
    }
  ]
}
```

For HTTP trigger (invoke on-demand from Logic Apps / a dashboard):

```json
{
  "bindings": [
    { "name": "req",  "type": "httpTrigger",  "direction": "in",  "authLevel": "function", "methods": ["post"] },
    { "name": "$return", "type": "http",     "direction": "out" }
  ]
}
```

#### 5.5 Logic App pattern (alternative)

For a low-code wrapper, a **Logic App** can call the Function App's HTTP trigger on a schedule
or in response to Defender / Sentinel events. Use a **system-assigned MI** on the Logic App
and grant it `Invoke` on the Function App's scope if you want auth without function keys.

The engine itself doesn't change between Function and Logic App hosts — both end up running
the same `launcher.community-azure.template.ps1`.

## Passing arguments to the engine

Many engines accept parameters that you'd previously pass to the v1 `Run*.ps1` files
(e.g. `-Summary`, `-Detailed`, `-Scope PROD`, `-ReportTemplate`). In v2 you have two
equivalent paths:

1. **Edit `LauncherConfig.ps1`** and set the corresponding global (preferred for
   unattended / scheduled runs):

   ```powershell
   # LauncherConfig.ps1
   $global:SpnTenantId     = '...'
   $global:SpnClientId     = '...'
   $global:SpnClientSecret = '...'

   # optional engine-level settings
   $global:ReportTemplate_Default = 'RiskAnalysis_Detailed_Bucket'
   $global:Mode_Default           = 'PROD'   # tagging: PROD / TEST
   ```

2. **Pass parameters directly to the launcher** (forwarded to the engine):

   ```powershell
   .\launcher.community-vm.template.ps1 -Summary
   .\launcher.community-vm.template.ps1 -Detailed -ReportTemplate 'RiskAnalysis_Detailed_Bucket_Test'
   .\launcher.community-vm.template.ps1 -Scope PROD            # for the tagging launchers
   ```

## Where samples live

- **Full sample data files** → `data/_samples/` (tagging + queries — use these as a copy-paste source for `data/*_Custom.yaml`).
- **Sample output reports** → `data/_samples/Sample - *.xlsx`.
- **Sample email bodies (AI summary)** → `data/_samples/Sample mail - *.pdf`.
- **All screenshots and diagrams** referenced from this README → `docs/Images/`.
- **Executive summaries, PDFs, Visio** → `docs/Documentation/`.

## Scheduling an unattended run

Create a Windows Scheduled Task that runs the launcher as your service account:

```
Program:    pwsh.exe
Arguments:  -NoProfile -ExecutionPolicy Bypass -File "<path>\SecurityInsight\launchers\SecurityInsight_RiskAnalysis\launcher.community-vm.template.ps1" -Summary
```

Replace `<path>` with wherever you cloned the repo. The launcher resolves everything else relative to itself.

------

# 🧪 Preview vs Stable — which branch should I use?

SecurityInsight is published in **two channels**, both to this same GitHub repo:

| Channel | Branch | What's here | Recommended for |
| --- | --- | --- | --- |
| **Stable** | `main` | Tagged releases (`v2.1.0`, `v2.1.1`, ...) with a matching GitHub Release + `SecurityInsight-vX.Y.Z.zip` asset. | **Production.** This is what you should run unless you explicitly want early-access features. |
| **Preview** | `preview` | Same content one release cycle ahead of stable. Gets a refresh whenever a `-preview` tag is cut upstream. No Release / zip asset — clone-only. | Labs, dev tenants, validating next release before it becomes stable. |

## Accessing each channel

**Stable** — default for everyone:

```powershell
# Download the release zip (recommended non-dev path)
# → https://github.com/KnudsenMorten/SecurityInsight/releases/latest

# …or clone the main branch:
git clone https://github.com/KnudsenMorten/SecurityInsight.git
```

**Preview** — opt in explicitly:

```powershell
# Fresh clone, preview branch:
git clone -b preview https://github.com/KnudsenMorten/SecurityInsight.git

# Already on main? Switch to preview:
cd SecurityInsight
git fetch origin
git checkout preview
git pull
```

## Switching back to stable

```powershell
cd SecurityInsight
git checkout main
git pull
```

Your `data/*_Custom.yaml`, `data/SecurityInsight_RiskIndex.csv`,
`data/SecurityInsight_IdentityTiering.json`, and
`launchers/<Engine>/LauncherConfig.ps1` files are preserved by the update rules — they are
never overwritten by a branch switch or a pull.

## When does something land on each branch?

1. Every change lands on the upstream monorepo (`KnudsenMorten/AutomateIT`) first.
2. Cutting a `SecurityInsight-vX.Y.Z-preview` tag publishes to this repo's **`preview`** branch.
3. After preview validation, cutting a `SecurityInsight-vX.Y.Z` tag publishes to **`main`**
   and creates a matching GitHub **Release** with the downloadable zip.

So the `preview` branch is always **ahead of or equal to** `main`. No surprise rollbacks.

## What can go wrong on preview (and how to recover)

Preview is meant to be stable enough to run, but it's not batch-tested like stable. If a
preview version misbehaves:

1. Switch back to stable: `git checkout main && git pull`.
2. Open an [Issue](https://github.com/KnudsenMorten/SecurityInsight/issues/new) with the
   preview tag you were on, the error, and the engine involved. See
   [Contributing, bugs & discussions](#-contributing-bugs--discussions) below.

------

# 📣 Contributing, bugs & discussions

SecurityInsight is a community-maintained add-on. Feedback and contributions are welcome.

## Report a bug or incident

Open a GitHub Issue:
[**New issue → KnudsenMorten/SecurityInsight**](https://github.com/KnudsenMorten/SecurityInsight/issues/new/choose)

What to include:

- **Version**: output of `git describe --tags` or the release tag you downloaded
  (e.g. `v2.1.2`), or `preview` + commit short SHA if you're on preview.
- **Engine**: which engine mis-behaved (e.g. `SecurityInsight_RiskAnalysis`).
- **Host**: VM / Azure Function / Logic App / Hybrid Worker.
- **Tenant shape** (rough): ~how many Defender devices, ~how many subscriptions, whether
  hybrid or cloud-only. This is often the difference between "works for me" and "reproduces".
- **What happened vs what you expected.**
- **Full error** (stack trace, not just the first line). Redact any tenant-specific identifiers
  before posting.
- **Last 20 lines of the transcript** (the engines write `Transcript_*.log` into the working
  folder).

Security-sensitive reports — don't use a public Issue. Email `mok@mortenknudsen.net` directly
with "`[SECURITY]`" in the subject. See [SECURITY.md](SECURITY.md) for the reporting policy.

## Feature request or question

Two good places:

- **[Discussions](https://github.com/KnudsenMorten/SecurityInsight/discussions)** — for
  open-ended questions, design conversations, "has anyone tried...". Less formal than Issues.
- **Issues** — for "I want this feature" with a specific, actionable description.

## Submit a pull request

This repo **accepts PRs directly**. See [CONTRIBUTING.md](CONTRIBUTING.md) for the exact flow:

- Fork → branch → commit → PR against `main`.
- Small fixes (typos, broken URLs, YAML sample additions) — welcome without prior discussion.
- Larger changes (new engine, scoring-model changes, new report template) — please open an
  Issue or Discussion first so we can align on shape before you write code.
- **Important:** this repo is auto-generated from the upstream `AutomateIT` monorepo. Accepted
  PRs are bridged upstream by the maintainer, and the next release republishes them here with
  your commit attribution preserved.

## Share your work

If you've built a useful **Custom YAML** (tagging rules or RiskAnalysis queries) for your own
tenant and think it might help others, open a Discussion thread under **Show & Tell**. Good
candidates get promoted into the platform `_Locked` YAMLs (with attribution) in a future
release.

## Help & resources

- **Author's blog:** https://mortenknudsen.net (alias https://aka.ms/morten) — deep-dives, release notes.
- **YouTube channel:** linked at the top of this README.
- **Discord / chat:** none (keeping coordination on GitHub).
- **Email:** mok@mortenknudsen.net (last resort — use Issues / Discussions first so others
  benefit from the answer).

------

# 🧰 Engines in this solution — what each one does

Every engine under `scripts/` has a matching launcher under `launchers/<EngineName>/`. Below is a
one-paragraph description of each, so you can pick the right one for the task at hand. For
exact run syntax, see [Installation & Running](#-installation--running) above.

## Engine: `CriticalAssetTagging`

Primary engine for **applying** SecurityInsight tier tags. Reads both
`data/SecurityInsight_CriticalAssetTagging_Locked.yaml` (platform-recommended queries) and
`data/SecurityInsight_CriticalAssetTagging_Custom.yaml` (your customer-specific rules), runs
each KQL query against Defender Exposure Graph / Azure Resource Graph, and tags matching assets
with the correct `<TagName>--tierN--SI` value. Supports `-SCOPE PROD` and `-SCOPE TEST` modes
(TEST runs the `Mode: Test` queries so you can validate new rules before promoting them to
`Mode: Prod`). Typically runs as a scheduled task every few hours.

## Engine: `CriticalAssetTaggingMaintenance`

**Read-only diagnostic + maintenance samples.** When run as-is, the script authenticates,
then executes a single hunting query that lists every tag currently applied to Defender devices
(useful for a quick estate inventory) — nothing is changed. Below a hard-stop `return`, the
file contains **four SAMPLE blocks** (each wrapped in `<# ... #>` and inert by default):

- **SAMPLE A** — remove ONE specific SI tier tag from every device that carries it.
- **SAMPLE B** — remove ALL SI tier tags (`--tier0--SI` .. `--tier3--SI`) from every device
  (full reset before re-running `CriticalAssetTagging` from scratch).
- **SAMPLE C** — remove a specific tag KEY from every Azure subscription that carries it.
- **SAMPLE D** — remove a specific tag KEY from every Azure resource that carries it.

To execute a sample: copy the block into its own script file (or uncomment inline), edit the
target tag name at the top, optionally set `$global:WhatIfMode = $true` for a dry run, and
execute. **Never uncomment and commit these back to the repo** — they are maintenance
utilities, not scheduled jobs.

## Engine: `CriticalAssetTaggingMaintenance_FixConflictingTags`

Resolves **tier-tag conflicts** on Defender devices. A device can legitimately pick up multiple
SI tier tags over time — for example a machine tagged `EmployeeWorkstation--tier3--SI` when it
was an ordinary laptop, and later also tagged `PAW--tier0--SI` when it was promoted to a PAW.
Without intervention the device ends up carrying both tags, and the lower-tier tag
(`tier3`) artificially dilutes the machine's blast-radius score.

This engine scans Defender Exposure Graph for any device with two or more `--tierN--SI` tags, keeps
the **highest-criticality** tag (lowest N — so tier 0 wins over tier 1, tier 1 over tier 2,
etc.), and removes every lower-tier `--tierN--SI` tag from that device. Non-SI tags are not
touched. Run it on a schedule (e.g. daily) alongside `CriticalAssetTagging`, or on-demand
after a tagging model change. Honours `$global:WhatIfMode` for a dry run.

## Engine: `Onboarding_IdentityAssets_LogAnalytics`

**One-time infrastructure provisioner** for the identity-asset telemetry pipeline that
`IdentityAssetsCollectDefineTierIngestLog` writes into. Run this engine **before** running
`IdentityAssetsCollectDefineTierIngestLog` for the first time in a tenant.

It provisions (idempotent — safe to re-run):

- A **Log Analytics workspace** (`log-platform-management-securityinsight` by default) in a
  target subscription + resource group.
- A **Data Collection Endpoint (DCE)** in the workspace region.
- A **Data Collection Rule (DCR)** bound to a custom table (`SI_IdentityAssets_CL`) that
  `IdentityAssetsCollectDefineTierIngestLog` sends its per-identity rows into.
- **RBAC**: grants the SecurityInsight SPN the minimum roles it needs to call the DCR
  ingestion endpoint (Monitoring Metrics Publisher on the DCR) and to read workspace
  metadata.

All target values (SubscriptionId, ResourceGroup, Location, WorkspaceName, DceName, DcrName,
TableName, retention days) are customer-tunable via `LauncherConfig.ps1` — edit the file under
`launchers/Onboarding_IdentityAssets_LogAnalytics/`. Sensible defaults are shipped if you
don't override.

**Recommended flow for a new tenant:**

1. Run `Onboarding_IdentityAssets_LogAnalytics` **once** to provision the workspace + DCE + DCR + RBAC.
2. (Optional) Run `Build_Tier_Definitions_JSON_File` to build a fresh tier catalogue.
3. Run `IdentityAssetsCollectDefineTierIngestLog` regularly (e.g. daily) to inventory + ingest.

## Engine: `IdentityAssetsCollectDefineTierIngestLog`

**Full identity-asset inventory with tier assignment.** This is the identity-plane counterpart
to the device-plane tagging engines. For every identity asset in the tenant — **users,
service principals, managed identities** — the script collects the **actual permissions**
currently assigned:

- **Active Directory** — group memberships, delegated ACLs, extended rights.
- **Entra ID roles** — both **permanent** role assignments and **eligible** (PIM) assignments.
- **Entra API / Graph application and delegated permissions** — the effective scope granted
  on every resource API the identity touches.
- **Azure RBAC** — role assignments at management group, subscription, and resource scope.

Each collected permission is then **correlated against the tier catalogue**
`SecurityInsight_IdentityTiering.json`, which maps every role / permission / API scope to a
tier (0 = full tenant takeover, 3 = low blast radius). The identity's **effective tier** is
the minimum across all providers (`min(AD, Entra roles, API permissions, Azure RBAC)`), so
one high-blast-radius permission is enough to drag an identity to tier 0.

The resulting per-identity tier assignment is ingested into your log store (Log Analytics / DCR)
so RiskAnalysis can consume it alongside device risk.

**Where it reads the tier catalogue from** (first existing file wins):

1. `SCRIPTS\Output\SecurityInsight_IdentityTiering.json` — freshly built by
   `Build_Tier_Definitions_JSON_File` (preferred; always up to date).
2. `DATA\SecurityInsight_IdentityTiering.json` — platform-shipped sample bundled with the
   solution. Used as a fallback if you haven't run the builder.

If you don't run `Build_Tier_Definitions_JSON_File` regularly, the shipped sample in `DATA/`
is good enough for most tenants. You only need to rebuild when Microsoft adds new
roles / permissions / API scopes and you want your tier assignments to reflect them.

## Engine: `Build_Tier_Definitions_JSON_File`

**Generates the `SecurityInsight_IdentityTiering.json` tier catalogue** used by
`IdentityAssetsCollectDefineTierIngestLog`. The flow:

1. Collects the **built-in permissions behind every role** across the identity plane:
   - AD built-in groups + extended rights.
   - Entra ID built-in roles.
   - Microsoft Graph application & delegated permissions.
   - Azure built-in RBAC roles (at all supported scopes).
2. For each role, assembles a **permission manifest** (what the role actually lets an
   attacker do).
3. Sends the manifest to **Azure OpenAI** (using the instance deployed by
   `Deploy_OpenAI_PAYG_Instance_SecurityInsights`). The AI evaluates each role against the
   SecurityInsight tier rubric (tier 0 → tier 3) and returns the recommended tier.
4. Aggregates all AI-recommended tiers into a single JSON file and writes it to
   `SCRIPTS\Output\SecurityInsight_IdentityTiering.json`.

This file is **the primary input** to `IdentityAssetsCollectDefineTierIngestLog` — if you
want your identity-plane risk scoring to reflect the latest Microsoft role changes, run this
engine on a cadence (weekly / monthly) or whenever Microsoft publishes notable role changes.

**Recommended cadence:** once a month (or on-demand when a high-privilege role is added or
deprecated by Microsoft). You can skip running it entirely and use the shipped
`DATA\SecurityInsight_IdentityTiering.json` sample — `IdentityAssetsCollectDefineTierIngestLog`
falls back to it automatically.

## Engine: `SecurityInsight_RiskAnalysis`

The risk-scoring engine that produces the Summary / Detailed Excel outputs plus the AI-summary
email. Reads `data/SecurityInsight_RiskAnalysis_Queries_Locked.yaml` +
`data/SecurityInsight_RiskAnalysis_Queries_Custom.yaml` for the KQL queries that define each
risk view; reads `data/SecurityInsight_RiskIndex.csv` for the scoring weights. Supports
`-Summary` and `-Detailed` modes and custom report templates via `-ReportTemplate`. See
the deep-dive in [Risk Score Model](#risk-score-model) below for the scoring math.

### Bucketing — how the engine handles queries that exceed Kusto's 30,000-row ceiling

Azure Resource Graph and Defender Exposure Graph both cap query results at **30,000 rows** per
call. Some of the RiskAnalysis queries (especially wide exposure joins across large estates)
legitimately return more than that. If a query overflows, Kusto / ARG returns one of a small
family of errors (`exceeded the allowed result size`, `exceeded the allowed limits`,
`preempted`, etc.). Without intervention, the engine would lose rows silently and skew the
risk scoring.

**The bucketing pattern solves this** by splitting the query into N deterministic partitions
that each stay under the row cap. The engine then unions the N partial results back into
one logical dataset before scoring.

**How it works** (implemented in `SecurityInsight_RiskAnalysis.ps1`):

1. **Placeholder in the KQL.** Each bucketable query has a single placeholder string
   (default `__BUCKET_FILTER__`) where the bucketing predicate will be injected at runtime.
   Example:
   ```kql
   ExposureGraphNodes
   | where NodeLabel has "device"
   __BUCKET_FILTER__
   | ...rest of the query...
   ```
2. **Bucket predicate generation.** At query-prep time the engine substitutes
   `__BUCKET_FILTER__` with a deterministic hash-based filter:
   ```kql
   | extend __bucket_key = coalesce(NodeId, NodeName, ...)
   | where isnotempty(__bucket_key)
   | extend __bucket = abs(hash(__bucket_key)) % <BucketCount>
   | where __bucket == <BucketIndex>
   ```
   With `BucketCount = 8`, one query becomes eight queries — each processing roughly an
   eighth of the dataset, all well under 30,000 rows.
3. **Union & dedupe.** Results from all N buckets are concatenated into one array; the
   scoring pipeline then runs unchanged on the unioned dataset.

### Auto-bucketing — the engine picks the bucket count itself

Manually guessing the right `BucketCount` for every query is brittle. The engine includes
an **adaptive probe** (`$global:AutoBucketCount = $true`) that:

1. **Probes.** Runs the query with `BucketCount = 1` (unbucketed). If Kusto returns an
   overflow error, retries with `2`, `4`, `8`, ... up to `$global:AutoBucketMax` (default 64).
2. **Caches the winning bucket count.** Once a bucket size succeeds, the engine caches the
   discovered value in `OUTPUT\AutoBucketCache.json` keyed by a **checksum of the query
   body**. The checksum guarantees the cache is invalidated automatically if the query is
   edited — so you never run a stale bucket count against a new query.
3. **Reuses on the next run.** Subsequent runs of the same query read the cache first and
   skip probing entirely. Probing only happens on first run or after a query change.

**Tunable knobs** (all via `$global:` or the launcher / `LauncherConfig.ps1`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `$global:UseQueryBucketing` | `$false` | Master switch. Per-query value in the YAML overrides this. |
| `$global:DefaultBucketCount` | `2` | Starting bucket count if not overridden per-query. |
| `$global:BucketPlaceholderToken` | `__BUCKET_FILTER__` | Token in the KQL that gets replaced. |
| `$global:AutoBucketCount` | `$false` | Enable adaptive probing. |
| `$global:AutoBucketMax` | `64` | Safety cap on probe size — never exceeds this. |
| `$global:AutoBucketCache` | `$true` | Persist discovered bucket counts to disk. |

To reset the cache (e.g. after Microsoft relaxes row limits, or you want to re-probe), delete
`OUTPUT\AutoBucketCache.json` — the engine will re-probe and rewrite it on the next run.

## Engine: `Deploy_OpenAI_PAYG_Instance_SecurityInsights`

One-shot deployer for the Azure OpenAI PAYG instance that `SecurityInsight_RiskAnalysis` uses
for the **AI summary** in emails, and that `Build_Tier_Definitions_JSON_File` uses to assign
tiers to roles. Idempotent — if the account / model deployment already exists at the target
names, the engine reuses them rather than re-creating. Customer values (SubscriptionId,
ResourceGroupName, Location, AccountName, DeploymentName, ModelName, Capacity) are set via
`LauncherConfig.ps1` or by editing the launcher template.

Only run this if you want the AI summary feature; the solution works without it (summary
email is skipped if no OpenAI endpoint is configured).

## Engine: `UpdateSecurityInsight` — subscribing to platform updates

**Purpose.** Let you "subscribe" to a curated list of SecurityInsight files and pull the
latest versions from the public GitHub repo on demand — without touching anything you have
customised locally.

### What you subscribe to (default)

Running `UpdateSecurityInsight` refreshes exactly these files from
`https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/main/`:

| Path | Type | Why it's subscribable |
| --- | --- | --- |
| `scripts/CriticalAssetTagging.ps1` | Engine | Frequently improved; new KQL patterns, new source types |
| `scripts/SecurityInsight_RiskAnalysis.ps1` | Engine | Scoring changes, new report templates, new AI logic |
| `scripts/IdentityAssetsCollectDefineTierIngestLog.ps1` | Engine | New identity sources, collector improvements |
| `scripts/Build_Tier_Definitions_JSON_File.ps1` | Engine | New role catalogue coverage, improved AI prompt |
| `data/SecurityInsight_CriticalAssetTagging_Locked.yaml` | Locked data | New recommended tagging rules |
| `data/SecurityInsight_RiskAnalysis_Queries_Locked.yaml` | Locked data | New recommended RiskAnalysis queries |

### What stays YOURS on every update

`UpdateSecurityInsight` **never touches**:

- `data/SecurityInsight_CriticalAssetTagging_Custom.yaml` — your customer-specific tags.
- `data/SecurityInsight_RiskAnalysis_Queries_Custom.yaml` — your custom KQL / reports.
- **`data/SecurityInsight_RiskIndex.csv`** — **customer-tunable** risk scoring weights. You
  adjust these to reflect your own priorities (e.g. increase the weight of PAW criticality
  in your environment). Never auto-overwritten.
- **`data/SecurityInsight_IdentityTiering.json`** — **customer-tunable** identity tier
  catalogue. You can override specific role tiers to match your governance model (e.g. classify
  an internal role you've added as tier 1 rather than tier 2). Regenerate locally by running
  `Build_Tier_Definitions_JSON_File` if you want a fresh AI-built version.
- `launchers/<Engine>/LauncherConfig.ps1` — your SPN credentials (`.gitignore`'d anyway).
- `launchers/<Engine>/launcher.override.ps1` — any per-launcher runtime overrides.
- `scripts/CriticalAssetTaggingMaintenance*.ps1` — one-off maintenance utilities.
- `scripts/Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1` — one-shot deployer.
- `scripts/Onboarding_IdentityAssets_LogAnalytics.ps1` — one-shot infra provisioner.
- `scripts/Output/SecurityInsight_IdentityTiering.json` — tenant-specific catalogue you built.

> **If you want to refresh one of the tunable files** (`SecurityInsight_RiskIndex.csv` or
> `SecurityInsight_IdentityTiering.json`) — for example to reset back to the platform
> defaults, or to see what changed upstream — pull it manually:
>
> ```powershell
> Invoke-WebRequest "$global:GitHubUri/data/SecurityInsight_RiskIndex.csv"        -OutFile ".\data\SecurityInsight_RiskIndex.csv"
> Invoke-WebRequest "$global:GitHubUri/data/SecurityInsight_IdentityTiering.json" -OutFile ".\data\SecurityInsight_IdentityTiering.json"
> ```
>
> Run from the solution root.

### How it runs

1. **Pre-flight:** ensures the local `BACKUP/` folder exists at the solution root.
2. **For each subscribed file:**
   - If a local copy exists → copy it to `BACKUP/<file>.<timestamp>.bak` (path separators are
     flattened so every backup lives in one folder).
   - Trim older backups for that file to keep the last 10 versions.
   - Download the fresh copy from the public repo and write to the corresponding path
     under the solution root (e.g. `scripts/` or `data/`).
3. **No auth required** — downloads come from the public GitHub raw URL, no SPN or API token needed.

### Adjusting the subscription

Edit the `$Files` array at the top of `scripts/UpdateSecurityInsight.ps1` to:

- **Remove** a line if you want that file frozen (e.g. you've heavily customised
  `SecurityInsight_RiskAnalysis.ps1` and don't want future versions to land automatically).
- **Add** a line if you want another file tracked (e.g. a maintenance script you've started
  to rely on).

Each entry is a path **relative to the public repo root** — examples:

```powershell
$Files = @(
    "scripts/CriticalAssetTagging.ps1",
    "data/SecurityInsight_RiskAnalysis_Queries_Locked.yaml",
    # add any file you want to subscribe to:
    "scripts/CriticalAssetTaggingMaintenance_FixConflictingTags.ps1"
)
```

### When to run it

- **Manually** whenever you want to pick up the latest curated improvements. A blog post or
  release note from the author will typically announce a new version.
- **Scheduled** weekly or monthly if you want to stay on the latest continuously. It's
  idempotent and safe to re-run — the backup/rotate logic means you always have the last
  10 versions of each file in `BACKUP/` if a new release introduces a regression.

### `UpdateSecurityInsight` vs `git pull` vs `Update-Platform.ps1`

| Method | When to use |
| --- | --- |
| `git pull` | If you cloned the public repo with `git clone`. Pulls every file the repo tracks, respects `.gitignore`. Simplest for developers. |
| `UpdateSecurityInsight` | Non-git install (you downloaded the repo as a zip), or you want to subscribe to a specific curated subset and ignore the rest. Has backup/rotation built in. |
| `Update-Platform.ps1` | Internal customers running the full AutomateIT monorepo release bundle. Updates across the whole platform (all solutions, all platform modules, the updater itself). |

All three honour the same rule: **customer-owned `*_Custom.*` and `LauncherConfig.ps1`
files are never touched.**

### Rollback

If a new version introduces a problem, revert from the backup:

```powershell
cd <solution-root>\BACKUP
# Find the last good backup
Get-ChildItem -Filter "scripts_SecurityInsight_RiskAnalysis.ps1.*.bak" | Sort-Object LastWriteTime -Descending
# Restore it
Copy-Item "scripts_SecurityInsight_RiskAnalysis.ps1.<timestamp>.bak" ..\scripts\SecurityInsight_RiskAnalysis.ps1 -Force
```

Then remove that file from `$Files` temporarily, until the issue is fixed upstream.

------

# Executive Summary

## 🧩 What it is

**SecurityInsight is a risk-based prioritization solution for Microsoft security findings.**

It rethinks traditional tools like Secure Score by introducing a **custom risk scoring model** based on:

- consequence (impact)
- probability (likelihood)
- contextual risk factors

Its core purpose is simple:

> **Help security teams decide what to fix first — based on real risk, not just severity.**



## 🚨 Problem it solves

**SecurityInsight addresses the lack of meaningful prioritization in modern security tooling.**

In typical environments:

- Thousands of vulnerabilities and recommendations exist
- Many are labeled "high" or "critical"
- Prioritization is based mostly on technical severity

**SecurityInsight solves this by:**

- Incorporating **business impact (asset criticality)**
- Considering **likelihood of exploitation**
- Understanding **relationships and attack paths**

👉 Instead of treating all findings equally, it highlights the ones that actually matter.



## ⚙️ How it works

### 🔢 Risk model

**SecurityInsight uses a simple core formula:**

Risk Score = Consequence × Probability

- **Consequence** → impact if exploited
- **Probability** → likelihood of exploitation

The score is further refined with contextual factors such as:

- Internet Exposure
- Contains Verified Secret
- Critical Resource
- Lateral Movement
- Sensitive Data
- LegacyEndOfSupport
- ExploitSignals → Vulnerability Exploitkit exist? Yes, choose before others



### 🏷️ Critical asset tagging

**SecurityInsight classifies assets by importance**, for example:

- **Tier-0 (Critical):** Global Admins, Domain Admins, break-glass accounts
- **Tier-1 / Tier-2 / Tier-3:** decreasing importance

👉 The same vulnerability becomes higher priority when it affects critical assets.



### 🕸️ Graph-based analysis

SecurityInsight uses graph-based security data (Exposure Graph) to:

- Map relationships between users, devices, identities, and resources
- Identify attack paths and lateral movement
- Correlate findings instead of treating them in isolation

👉 This aligns defensive prioritization with how attackers actually operate.



### 🧮 Risk analysis engine

**SecurityInsight includes a PowerShell-based analysis engine that:**

- Executes Kusto (KQL) queries against Microsoft security data
- Processes graph data (nodes + edges)
- Applies the risk model
- Produces a prioritized **risk index**

Core components:

- `RunSecurityInsight.ps1` (entry point)
- Risk analysis scripts
- KQL query definitions (YAML)
- Risk index configuration (CSV)



### 📊 Reporting

**SecurityInsight generates actionable outputs such as:**

- Summary reports
- Detailed findings
- Prioritized remediation lists

Optional:

- AI-generated summaries via OpenAI integration



## 💡 Key idea

> **SecurityInsight transforms raw security findings into a prioritized, business-aware risk view.**

------



# The Challenge: Too Many Security Recommendations

Modern security platforms such as Microsoft Defender generate a very large number of security recommendations, vulnerabilities, and configuration findings. Security teams are often faced with:

- thousands of vulnerabilities
- hundreds of security recommendations
- many findings marked as High or Critical

Traditional vulnerability management often focuses on CVSS scores or severity classifications. This approach creates several challenges:

- the same vulnerability is evaluated equally regardless of the asset
- business impact is not considered
- attack chains and relationships are not identified

Although these tools are effective at identifying problems, they rarely answer the most important question: **Which issues should be addressed first?**

In practice, remediation work is often prioritized according to:

- technical severity
- number of affected systems
- ease of remediation

This often leads organizations to spend resources resolving issues with limited real risk while more critical exposures remain unaddressed.

------



# A Risk-Based Prioritization Model

The **SecurityInsight** framework introduces a **risk-based prioritization model** that evaluates security findings based on both consequence and probability.

```
Risk Score = Consequence Score × Probability Score
```

**Consequence Score** represents the potential impact if a vulnerability is exploited.

**Probability Score** represents the likelihood that the vulnerability will actually be exploited.

The model can also be influenced by **contextual risk factors** such as:

- Internet Exposure
- Contains Verified Secret
- Critical Resource
- Lateral Movement
- Sensitive Data
- LegacyEndOfSupport
- ExploitSignals → Vulnerability Exploitkit exist? Yes, choose before others
- +more can be added along the way

These factors will each increase the probability score with +1 — and therefore indirectly increase the overall risk score.

------



# Why We Use a Graph — Understanding Exposure Graph Architecture

**Defenders typically think in lists.** Security tools often present data as separate inventories such as:

- Devices
- Users
- Software
- Vulnerabilities
- Cloud resources

These lists help with management and reporting, but they **do not show how systems interact with each other**.

**Attackers, however, do not think in lists.** They think in **relationships between systems** and look for ways to move laterally through an environment. Instead of focusing on individual assets, they focus on **how one compromised system can lead to another**.

This is why modern security platforms like **Microsoft Exposure Graph** represent security data as a **graph of connected entities** rather than isolated lists.

A graph structure allows security tools such as **Microsoft Defender** and **Microsoft Security Copilot** to map relationships between users, devices, applications, and privileges.

------



## Example of an Attack Path

A typical attack rarely targets the most critical system directly. Instead, attackers move through connected systems step by step.

For example:

```
User device → Application server → Service account → Domain Controller
```

This path can represent the following scenario:

1. An attacker compromises a **user device** through phishing or malware.
2. That device has access to an **application server**.
3. The application server runs using a **service account**.
4. The service account has elevated privileges on the **domain controller**.

By following this chain of relationships, the attacker can eventually gain control of the **domain controller**, even though the original compromise happened on a normal user machine.



### Example of Attack Path

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/AttackPath-Sample-EntraCookie-1.png)

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/AttackPath-Sample-EntraCookie-2.png)

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/AttackPath-Sample-EntraCookie-3.png)

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/AttackPath-Sample-EntraCookie-4.png)

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/AttackPath-Sample-EntraCookie-5.png)

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/AttackPath-Sample-EntraCookie-6.png)

------



## Why Graph Architecture Matters

A **graph model** allows security platforms to:

- **Map relationships between assets**
- **Identify possible attack paths**
- **Detect lateral movement opportunities**
- **Prioritize exposures that could lead to high-impact compromise**

Instead of asking *"What vulnerabilities exist?"*, a graph-based system asks:

> *"Which vulnerabilities could actually lead to a critical system being compromised?"*

This relationship-based view is what makes exposure graphs powerful for **modern threat detection and attack path analysis**.

The **SecurityInsight model** therefore uses **Exposure Graph** analysis to identify relationships between assets, identities, vulnerabilities and configuration issues. Data is sourced from:

- ExposureGraphNodes
- ExposureGraphEdges
- Defender Vulnerability Management findings
- Configuration assessments

These datasets allow analysis of relationships between systems and security findings.

------



# Risk Score Model

**Risk Score** is calculated using two dimensions:

**Consequence Score** – the potential impact if exploitation occurs.

**Probability Score** – the likelihood of exploitation based on asset tier and exposure context.

**Probability Score** may be adjusted using **contextual risk indicators (risk factors)** that increase the likelihood of exploitation, such as:

- **Active exploitation:** If the vulnerability is currently being exploited in the wild, the likelihood of compromise is significantly higher.
- **Public exploit code:** Proof-of-concept exploit code is publicly available, lowering the barrier for attackers to exploit the vulnerability.
- **Internet exposure:** Systems accessible from the internet increase the likelihood of exploitation.
- **Legacy systems:** Older or unsupported systems may lack security updates and increase vulnerability risk.
- Contains Verified Secret
- Critical Resource
- Lateral Movement
- Sensitive Data

Each of these influences the score by increasing the probability score with +1 due to the risk factor.

Future possible risk factors being considered are:

- **Large attack surface** – The system exposes multiple services, APIs, or open ports that increase discovery and exploitation opportunities.
- **Third-party exposure** – The system is accessible by external partners, vendors, or suppliers.
- **Shared infrastructure** – The vulnerable system is shared across many users or business units, increasing attacker opportunity.
- **Weak network segmentation** – The system is poorly isolated, allowing attackers easier lateral movement once access is gained.
- **Credential exposure risk** – The environment has higher likelihood of credential compromise (e.g., shared accounts, weak MFA adoption).
- **Remote access enabled** – Services such as VPN, RDP, SSH, or remote administration interfaces increase potential entry points.

The **final risk score** is calculated as:

**Risk Score = Consequence Score × Probability Score**

This score is used to prioritize remediation activities.

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/Riskscore-Sample-Zoom.png)

Line #1 with score of 20 is the most critical thing to fix, based on the calculation. Then the next lines with risk score 15, 12, 10, etc.

Calculation sample (line #1):

```
Severity: 4
Probability: 5 (4 + 1 due to risk factor 'internet exposed'). 4 is coming from risk index
Risk Score: 20 (4 x 5)
```

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/Riskscore-Sample.png)



#### Another example with more risk factors impacting risk score

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/RiskFactorsSamples.png)



### Severity Prioritization | Risk Score Definitions

**Disclaimer:** The severity scores and risk impact classifications presented here are based on my own professional judgment and experience working with attacker-centric security frameworks. Actual exploitation impact may vary depending on each organization's specific environment, existing detective and preventive controls, risk tolerance, regulatory requirements, and architectural decisions. Scores should be used as a prioritization guide, not as absolute measures of risk.

| Defender Score | Risk Impact | Attack Impact |
| ----------------------- | ------------------------------- | ------------------------------------------------------------ |
| 10                      | Very High                       | **Absence of this control gives attackers an immediate and decisive advantage.** <br/><br/>Either a critical attack path is left fully exposed, or a single exploitation leads directly to full environment compromise with no further steps required. |
| 9                       | High                            | This control addresses **weaknesses that are actively weaponized in the wild by ransomware operators, credential theft campaigns, and advanced persistent threat actors**. <br/><br/>Exploitation is well-documented, tooling is widely available, and remediation should be treated as urgent. |
| 8                       | Medium-High                     | This control is a **foundational hardening measure that meaningfully shrinks the attack surface and disrupts common lateral movement techniques**. <br/><br/>While not immediately catastrophic if missing, its absence creates conditions that attackers routinely chain together to escalate privileges or move laterally. |
| 5-7                     | Medium                          | This control reflects **established security best practice and reduces exposure to known attack patterns**. <br/>Exploitation is possible but less consistent, typically requiring specific environmental conditions or attacker patience. Prioritize after higher-severity items are addressed. |
| 1-4                     | Low                             | This control contributes to **security hygiene and long-term posture improvement**. <br/><br/>Missing controls in this range are unlikely to be directly targeted but may marginally increase the cost or noise for an attacker operating in the environment. |



### Criticality Prioritization | Risk Score Definitions

**Disclaimer:** The asset criticality classifications and attacker-centric tiering presented here are based on my own professional judgment and experience working with identity, endpoint, and cloud security environments. Actual tier assignments may vary depending on each organization's specific architecture, hybrid connectivity model, existing compensating controls, risk tolerance, regulatory requirements, and operational priorities. Classifications should be used as a strategic prioritization framework, not as a definitive or exhaustive measure of asset risk.

| Criticality Level | Attack Impact | Defender terms |
| --------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| **Critical<br />(Tier-0)**                    | **Immediate full environment compromise if taken**<br />Compromise of a Domain Controller, krbtgt account, or Global Administrator yields unrestricted control over every identity, credential, and resource in the environment.<br /><br />An attacker can forge Kerberos tickets, replicate the entire AD database, assign any Entra role, and persist indefinitely without detection. Recovery requires full forest rebuild. | **Portal:** Very High - tier 0 <br /><br />**API:** 0 |
| **High<br />(Tier-1)**                        | **High impact, one or two pivots to full compromise**<br />Compromise of an Exchange server, Authentication Administrator, or jump server provides credential material, token abuse opportunities, or lateral movement paths that lead to tier 0 within one or two steps. <br /><br />An attacker can reset MFA, intercept authentication flows, abuse unconstrained delegation, or exploit ADCS misconfigurations to escalate without direct access to tier 0 assets. | **Portal:** High - tier 1<br />**API:** 1 |
| **Medium<br />(Tier-2)**                      | **Significant workload impact, conditional path to escalation**<br />Compromise of a file server, developer workstation, or SharePoint environment enables mass data exfiltration, credential harvesting from application configs, and abuse of scoped service accounts.<br /><br />Escalation to tier 0 is possible but requires chaining multiple weaknesses such as finding reused credentials, misconfigured delegation, or an over-permissioned service principal. | **Portal:** Medium - tier 2 <br />**API:** 2 |
| **Low<br />(Tier-3)**                         | **Low blast radius, limited lateral movement potential**<br />Compromise of a standard employee workstation, guest PC, or read-only service account yields limited immediate value.<br /><br />An attacker gains a foothold for phishing, internal reconnaissance, or credential capture via keylogging, but cannot directly access sensitive systems or escalate without exploiting additional misconfigurations elsewhere in the environment. | **Portal:** Low - tier 3 <br />**API:** 3 |



### Identity Asset Criticality Classification

**Disclaimer:** The asset criticality classifications and attacker-centric tiering presented here are based on my own professional judgment and experience working with identity, endpoint, and cloud security environments. Actual tier assignments may vary depending on each organization's specific architecture, hybrid connectivity model, existing compensating controls, risk tolerance, regulatory requirements, and operational priorities. Classifications should be used as a strategic prioritization framework, not as a definitive or exhaustive measure of asset risk. List is not complete.

| Criticality Level | Typical Assets |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| **Critical<br />(Tier-0)**<br /><br />Immediate Domain Takeover | **Entra ID Roles (built-in) – users/managed identities:** Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Partner / GDAP Delegated Admin, Directory Synchronization Accounts, Hybrid Identity Administrator (when Entra Connect is in password hash sync mode)<br /><br />**Application Permissions (Graph / API):** RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All, AppRoleAssignment.ReadWrite.All, Policy.ReadWrite.AuthenticationMethod, PrivilegedAccess.ReadWrite.AzureAD, RoleManagement.ReadWrite.CloudPC, Organization.ReadWrite.All, Domain.ReadWrite.All, CrossTenantUserProfileSharing.ReadWrite.All, OnPremDirectorySynchronization.ReadWrite.All<br /><br />**Azure Built-in Roles:** Owner (root management group), User Access Administrator (root management group), Owner (tenant root subscription)<br /><br />**Azure Permissions:** Contributor + blueprint assign (root MG), Managed Identity Contributor (root scope), Entra ID joined device with Global Admin token cache, Subscription Owner with Az AD write federation<br/><br/>**AD Built-in Groups:** Domain Admins, Enterprise Admins, Schema Admins, Administrators (builtin), Group Policy Creator Owners, Cert Publishers, Domain Controllers group<br/><br/>**AD Permissions:** Replication rights (DCSync), DnsAdmins (with DC write), SYSTEM on any DC<br /><br />**Accounts (list not complete):** krbtgt account, SYSTEM on DC, Entra Connect sync account (MSOL_), ADConnect service account, Break-glass emergency access accounts, Service accounts with DCSync rights, Accounts with AdminSDHolder propagated ACLs |
| **High<br />(Tier-1)**<br /><br />Fast-Track Takeover (Abusable Privileges) | **Entra ID Roles (built-in) – users/managed identities:** Authentication Administrator, Hybrid Identity Administrator, Exchange Administrator, Cloud App Administrator, Application Administrator, Security Administrator, Intune Administrator, Identity Governance Administrator, External Identity Provider Administrator, B2C IEF Policy Administrator, Domain Name Administrator, Password Administrator (when targeting admins), Helpdesk Administrator (when targeting admins), Billing Administrator, Azure DevOps Administrator, Windows 365 Administrator<br/><br/>**Application Permissions (Graph / API):** Application.ReadWrite.All, Mail.ReadWrite (app all users), User.ReadWrite.All, Group.ReadWrite.All, Sites.FullControl.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementApps.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, ServicePrincipalEndpoint.ReadWrite.All, Policy.ReadWrite.ConditionalAccess, Policy.ReadWrite.PermissionGrant, EntitlementManagement.ReadWrite.All, PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup, AuthenticationContext.ReadWrite.All, TrustFrameworkKeySet.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All, IdentityProvider.ReadWrite.All, Organization.ReadWrite.All, Domain.ReadWrite.All, AccessReview.ReadWrite.All, Agreement.ReadWrite.All, RoleEligibilitySchedule.ReadWrite.Directory, RoleAssignmentSchedule.ReadWrite.Directory<br /><br />**Azure Built-in Roles (list not complete):** Owner (subscription or resource group), User Access Administrator (subscription scope), Key Vault Administrator, Azure Kubernetes Service Cluster Admin, Managed Identity Operator (on high-privilege MIs), Virtual Machine Contributor, Automation Account Contributor, Logic App Contributor<br/><br/>**Azure Permissions (list not complete):** Contributor on Key Vault (with access policy model), Azure Arc onboarding with connected machine agent, Storage Account Contributor (with Entra-integrated storage), Azure DevOps project admin (with service connection to high-priv MI), Defender for Cloud admin, IMDS token theft via VM access, Runbook execution as managed identity<br /><br />**AD Built-in Groups:** Account Operators, Backup Operators, Server Operators, Print Operators<br/><br/>**AD Permissions (list not complete):** GPO edit rights on tier 0 OUs, AdminSDHolder write access, msDS-KeyCredentialLink write, WriteOwner on domain root, WriteDACL on domain root, GenericAll on tier 0 groups, GenericWrite on Domain Controllers OU, AllExtendedRights on domain root, ForceChangePassword on admin accounts, Manage CA (AD CS), Certificate enrollment agents, ESC1–ESC8 vulnerable certificate templates, SeBackupPrivilege holders, SeRestorePrivilege holders, SeTakeOwnershipPrivilege holders, SeDebugPrivilege on DC, SeImpersonatePrivilege on DC, Unconstrained delegation computers, Unconstrained delegation service accounts, Shadow Credentials write on admin accounts, SID History injection rights, Trust account manipulation rights, GPO link rights on tier 0 OUs, OU owner on Domain Controllers OU<br /><br />**Accounts (list not complete):** Entra Connect service account, High-privilege service principals with T0 Graph permissions, Admin-consented OAuth apps with T1 permissions, AD CS enrollment agent accounts, Service accounts with unconstrained delegation, Accounts with GenericAll on tier 0 objects, Federated identity credentials on high-privilege app registrations, Managed identities with Owner or UAA at subscription scope, Workload identities bound to high-privilege Azure RBAC roles, Azure Automation Run As accounts, Service principals with client secrets stored in Key Vault accessible to lower-trust identities |
| **Medium<br />(Tier-2)**<br /><br />Conditional Takeover (Needs Chaining / Misconfig) | **Entra ID Roles (built-in) – users/managed identities (list not complete):** User Administrator, Groups Administrator, Conditional Access Administrator, SharePoint Administrator, Teams Administrator, Lifecycle Workflows Administrator<br/><br/>**Application Permissions (Graph / API) (list not complete):** Mail.Read (app all users), Calendars.ReadWrite, Files.ReadWrite.All, AuditLog.Read.All, IdentityRiskyUser.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All<br/><br/>**Azure Built-in Roles (list not complete):** Network Contributor, Log Analytics Contributor, Automation Operator, Azure DevOps stakeholder, Azure Kubernetes Service Cluster User<br /><br />**Azure Permissions (list not complete):** Contributor (single non-sensitive resource group), Storage Blob Data Reader (scoped to non-sensitive storage), Log Analytics Reader, Monitoring Reader, Security Reader (Defender for Cloud), Managed Identity on low-privilege workload, Service principal scoped to single resource group<br/><br />**AD Built-in Groups:** DNS Admins<br/><br />**AD Permissions (list not complete):** OU-scoped write ACLs, LAPS read rights, Constrained delegation (msDS-AllowedToDelegateTo), RBCD write rights, Kerberoastable high-priv SAs<br/><br />**Accounts (list not complete):** High-privilege service principals scoped to workload, Admin-consented OAuth apps with scoped permissions, Automation accounts with limited RBAC, Azure DevOps service connections scoped to single subscription |
| **Low<br />(Tier-3)**<br /><br />Low blast radius, limited lateral movement potential | **Entra ID Roles (built-in) – users/managed identities:** Global Reader, Security Reader, Reports Reader, Message Center Reader, Usage Summary Reports Reader, Directory Readers, Guest User (default)<br/><br/>**Application Permissions (Graph / API) (list not complete):** User.Read (delegated), Mail.Read (delegated self), Calendars.Read (delegated), Directory.Read.All, AuditLog.Read.All (delegated), IdentityRiskEvent.Read.All<br/><br/>**Azure Built-in Roles (list not complete):** Reader (subscription or resource group), Billing Reader, Cost Management Reader, Tag Contributor, Azure DevOps Basic user (no pipeline access)<br /><br />**Azure Permissions (list not complete):** Storage Blob Data Reader (scoped, non-sensitive), Managed Identity with Reader only, Service principal with Reader on isolated resource group<br/><br/>**AD Built-in Groups:** Domain Users (default), Read-only DC (RODC)<br/><br/>**AD Permissions (list not complete):** Scoped helpdesk OU read, GenericRead on non-priv objects<br /><br />**Accounts (list not complete):** Standard user accounts, Guest accounts, Read-only service accounts, Managed identities with no RBAC assignments, Expired or disabled service principals |



### Endpoint / Device Asset Criticality Classification

**Disclaimer:** The asset criticality classifications and attacker-centric tiering presented here are based on my own professional judgment and experience working with identity, endpoint, and cloud security environments. Actual tier assignments may vary depending on each organization's specific architecture, hybrid connectivity model, existing compensating controls, risk tolerance, regulatory requirements, and operational priorities. Classifications should be used as a strategic prioritization framework, not as a definitive or exhaustive measure of asset risk. List is not complete.

| Criticality Level | Typical Assets |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| **Critical<br />(Tier-0)**<br /><br />Immediate full environment compromise if taken | **Server Roles:** Domain Controllers (Primary/Additional), Read-Only Domain Controllers (RODC), AD CS servers (Certificate Authority — root and subordinate), Entra Connect / AD Connect servers, Federation servers (AD FS primary)<br/><br/>**Management:** Privileged Access Workstations (PAW) used by tier 0 admins, Backup servers with DC/CA backup data, Monitoring servers with domain-level agent credentials, Key Management Services (KMS) servers with domain-joined credential store<br/><br/>**Infrastructure:** HSM-attached servers (storing root CA private keys), SAN / storage controllers backing tier 0 VMs<br/><br/>**Hypervisor:** Hypervisor hosts running tier 0 guest VMs (VMware ESXi, Hyper-V, KVM), vCenter / SCVMM management servers (managing tier 0 hypervisors)<br/><br/>**Network Equipment:** Core routers (BGP, MPLS backbone), Core switches (spanning all VLANs), Firewall clusters (perimeter and internal segmentation), Out-of-band management network devices (iDRAC, iLO, IPMI), Network management servers (Cisco DNA, SolarWinds — full network write access), SD-WAN controllers, Load balancers (handling auth traffic)<br/><br/>**IoT / OT:** Building management systems (BMS) controllers with domain integration, Physical security controllers (badge access, CCTV management) with domain integration, OT / ICS controllers with direct network adjacency to tier 0 systems |
| **High<br />(Tier-1)**<br /><br />High impact, one or two pivots to full compromise | **Server Roles:** Exchange servers, MFA / RADIUS servers, PKI subordinate CA servers, DNS servers (non-DC hosted), Active Directory Federation Services (AD FS) proxy servers<br/><br/>**Management:** Privileged Access Workstations (PAW) used by tier 1 admins, Jump servers / bastion hosts, SIEM servers, Endpoint Detection and Response (EDR) management servers, SCCM / MECM primary site servers, Privileged Identity Management (PIM) approval workflow servers, Secret management servers (HashiCorp Vault, Azure Key Vault private endpoints), Password managers with admin credential stores, Patch management servers (WSUS), Admin workstations used by tier 1 staff without PAW controls<br/><br/>**Infrastructure:** Network Access Control (NAC) servers, VPN concentrators / remote access servers, Azure Arc-connected servers with high-privilege managed identity, Privileged developer machines with production secrets or pipeline credentials<br/><br/>**Hypervisor:** Hypervisor hosts running tier 1 guest VMs, vCenter / SCVMM management servers (managing tier 1 hypervisors)<br/><br/>**Network Equipment:** Distribution switches, Wireless LAN controllers (WLC), Proxy servers (SSL inspection — credential visibility), RADIUS / TACACS+ network authentication servers, Network packet brokers / TAP aggregators, Remote access concentrators (Citrix ADC, F5 BIG-IP), DNS resolvers (internal recursive), DHCP servers (domain-integrated), Network time protocol (NTP) primary servers<br/><br/>**IoT / OT:** SCADA / ICS servers (non-tier 0 adjacent), Industrial IoT gateways with network bridging, UPS management controllers (power disruption potential), HVAC controllers (data center environment impact), Building automation system (BAS) servers, Medical device management servers, Surveillance / CCTV management servers (non-domain integrated)<br/><br/>**Client Devices:** IT staff personal workstations (helpdesk, sysadmin, network engineers — cached credentials, admin tools, RDP session history), IT management laptops (used for remote administration without formal PAW controls), Security operations workstations (SOC analyst machines with SIEM and EDR console access), Senior IT personal workstations (IT managers, architects — broad access scope) |
| **Medium<br />(Tier-2)**<br /><br />Significant workload impact, conditional path to escalation | **Server Roles:** File servers, SharePoint servers, SQL servers hosting sensitive databases, Citrix / RDS session hosts, Web application servers with Entra integrated auth, API gateway servers, Collaboration servers (Teams on-prem, Skype for Business), HR and identity lifecycle management servers, Internal certificate registration authority (RA) servers, IT service management servers (ServiceNow, Jira)<br/><br/>**Management:** Log aggregation servers, DevOps / CI-CD build agents, Container orchestration nodes (Kubernetes worker nodes)<br/><br />**Hypervisor:** Hypervisor hosts running tier 2 guest VMs<br/><br/>**Network Equipment:** Access layer switches (user-facing VLANs), Wireless access points (managed), Network monitoring appliances (read-only), Standalone DHCP servers (non-domain integrated), Content filtering / web proxy appliances, VoIP / SIP gateways<br/><br/>**IoT / OT:** Smart meeting room devices (displays, conferencing systems), Environmental sensors (temperature, humidity — data center), Badge readers (non-domain integrated, isolated), Laboratory equipment with network interfaces, IP cameras (isolated VLAN, no domain integration), Industrial sensors (read-only, no control plane access), Retail / POS terminals (isolated network segment)<br/><br/>**Client Devices:** Production workstations, Lab workstations, Shared devices, Developer workstations, Power user workstations (finance, legal, HR) |
| **Low<br />(Tier-3)**<br /><br />Low blast radius, limited lateral movement potential | **Server Roles:** Print servers, DHCP servers, Time servers (NTP), VoIP servers, Internal wiki / intranet servers, Archival / cold storage servers, Physical access control servers, Test / sandbox servers<br/><br/>**Management:** Network monitoring probes<br/><br/>**Network Equipment:** Unmanaged access switches, Consumer-grade wireless access points, Out-of-band console servers (isolated, read-only access), Standalone print servers (network-connected, no domain join)<br/><br/>**IoT / OT:** Smart lighting controllers (isolated network), Consumer IoT devices (isolated guest VLAN), Non-networked or air-gapped sensors, Vending machines / coffee machines with network connectivity, Digital signage players (isolated, read-only content), Wearables / smart badges (no domain integration), USB-only peripheral devices with firmware update capability<br/><br/>**Client Devices:** Standard employee workstations, Student workstations, Kiosk machines, Guest PCs, Shared classroom / library computers, Development workstations (non-privileged, isolated, no production access), Personally-owned BYOD devices, Retired / decommissioned machines |



### Cloud (Azure) Asset Criticality Classification

**Disclaimer:** The asset criticality classifications and attacker-centric tiering presented here are based on my own professional judgment and experience working with identity, endpoint, and cloud security environments. Actual tier assignments may vary depending on each organization's specific architecture, hybrid connectivity model, existing compensating controls, risk tolerance, regulatory requirements, and operational priorities. Classifications should be used as a strategic prioritization framework, not as a definitive or exhaustive measure of asset risk. List is not complete.

| Criticality Level | Typical Assets |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| **Critical<br />(Tier-0)**<br /><br />Immediate full environment compromise if taken | **Compute:** Virtual Machines hosting tier 0 workloads (DC, ADCS, Entra Connect), Virtual Machines with privileged tokens or highly privileged managed identities assigned, VM Scale Sets running privileged workloads, Azure Bastion hosts (gateway to tier 0 VMs), Confidential compute instances handling key material<br/><br/>**Storage:** Storage accounts containing DC/CA backup data, Storage accounts containing Entra Connect configuration, Azure Blob Storage backing tier 0 audit and log pipelines, Storage accounts with Entra-integrated RBAC and tier 0 data, Immutable and locked Azure Storage holding identity bootstrap data<br/><br/>**Identity & Access:** Entra ID tenant root, Management group root (tenant root group), Subscriptions containing tier 0 workloads, Azure Key Vault storing root CA private keys, Azure Key Vault storing tenant-wide secrets and certificates, Azure Key Vaults storing tenant root keys or certificate authorities, Managed Identity with Owner or User Access Administrator at subscription or MG scope, App registrations with RoleManagement.ReadWrite.Directory or Directory.ReadWrite.All, Service principals with tenant-wide privileged Graph API permissions<br/><br/>**Networking:** Virtual Networks hosting tier 0 VMs, Network Security Groups governing tier 0 subnet traffic, Azure Firewall (central hub — controls all east-west and north-south traffic), ExpressRoute circuits (direct on-prem to cloud bridge), Azure Private DNS zones (name resolution for tier 0 services), VPN Gateways (site-to-site tunnels into on-prem tier 0 networks), Azure DDoS Protection plans, Azure Network and Security Policy control plane resources<br/><br/>**Management & Governance:** Azure Management Groups with root tenant-level access, Azure Subscription Owner roles over security-critical subscriptions, Azure Policy assignments at root MG scope, Azure Blueprints assigned at root MG scope, Microsoft Defender for Cloud, Azure Monitor (Log Analytics workspaces ingesting tier 0 signals), Microsoft Sentinel workspace, Azure Automation accounts running as high-privilege managed identity, Azure Automation / Runbook accounts with privileged role assignments, Azure DevOps organizations with service connections to tier 0 subscriptions, Azure Arc control plane (manages on-prem servers as Azure resources), Azure Arc / Hybrid management orchestrators<br/><br/>**Hypervisor / Fabric:** Azure Dedicated Hosts running tier 0 VMs, Azure VMware Solution (AVS) management clusters, Azure Stack HCI clusters running tier 0 guest VMs |
| **High<br />(Tier-1)**<br /><br />High impact, one or two pivots to full compromise | **Compute:** Virtual Machines hosting Exchange, ADFS, MFA, or SIEM workloads, Virtual Machines with scoped privileged tokens or identities, Azure Kubernetes Service (AKS) clusters with privileged workloads, Azure Container Apps running privileged services, Azure Batch accounts with high-privilege managed identity<br/><br/>**Storage:** Storage accounts backing SIEM and log aggregation, Storage accounts containing application secrets or config, Azure File shares mounted by privileged VMs, Azure Data Lake storing sensitive identity or security telemetry, Highly active Azure Key Vaults with large number of operations<br/><br/>**Identity & Access:** App registrations with Application.ReadWrite.All or User.ReadWrite.All, Service principals with Exchange, Intune, or Security Administrator equivalent permissions, Managed Identities with Contributor or Key Vault Administrator at subscription scope, Azure AD B2C tenants federated to production tenant, Federated identity credentials on privileged app registrations<br/><br/>**Networking:** Hub Virtual Networks (peered to tier 0 VNets), Azure Application Gateway (WAF — handles auth traffic), Azure Front Door (global entry point — SSL termination), Azure Load Balancer (fronting tier 1 workloads), Network Virtual Appliances (NVA — routing and inspection), Azure Private Endpoints for tier 1 services, Azure DNS resolvers (recursive — name resolution for all workloads)<br/><br/>**Management & Governance:** Azure Automation accounts with scoped privileged runbooks, Azure Automation / Runbook accounts with scoped role assignments, Log Analytics workspaces ingesting tier 1 signals, Azure DevOps pipelines deploying to tier 1 environments, Azure Key Vault storing tier 1 application secrets, Microsoft Defender for Endpoint, Azure Update Manager, Azure Lighthouse delegations with privileged access, Azure Arc / Hybrid management orchestrators (scoped to tier 1 systems)<br/><br/>**Hypervisor / Fabric:** Azure Dedicated Hosts running tier 1 VMs, Azure Stack HCI clusters running tier 1 guest VMs, Azure VMware Solution (AVS) workload clusters |
| **Medium<br />(Tier-2)**<br /><br />Significant workload impact, conditional path to escalation | **Compute:** Virtual Machines hosting file, SharePoint, SQL, or collaboration workloads, Azure Kubernetes Service (AKS) worker nodes (non-privileged workloads), Azure App Service plans hosting internal applications, Azure Functions with scoped managed identity, Azure Logic Apps with limited connector scope, Azure Virtual Desktop (AVD) / Windows 365 for non-admin users, Dev/Test virtual machines without production data<br/><br/>**Storage:** Storage accounts hosting application data (non-sensitive), Azure SQL databases (non-sensitive schemas), Azure Cosmos DB instances (application data), Azure File shares mounted by standard workload VMs, Azure Blob Storage for application asset delivery<br/><br/>**Identity & Access:** App registrations with scoped delegated permissions, Service principals scoped to single resource group, Managed Identities with Contributor on isolated resource group, App registrations with Mail.Read or Files.ReadWrite.All<br/><br/>**Networking:** Spoke Virtual Networks (workload-specific, peered to hub), Azure Application Gateway (non-auth workloads), Network Security Groups on workload subnets, Azure Traffic Manager profiles, Azure Content Delivery Network (CDN) endpoints<br/><br/>**Management & Governance:** Dev/Test subscriptions and resource groups, Non-production workloads (dev, test, QA, staging) without production data, Azure DevOps pipelines deploying to tier 2 environments, Log Analytics workspaces (workload-scoped), Azure Key Vault storing tier 2 application secrets, Azure Monitor alert rules (workload-scoped), Azure Backup vaults (tier 2 workload data)<br/><br/>**Hypervisor / Fabric:** Azure Dedicated Hosts running tier 2 VMs, Azure Stack HCI clusters running tier 2 guest VMs |
| **Low<br />(Tier-3)**<br /><br />Low blast radius, limited lateral movement potential | **Compute:** Virtual Machines hosting non-sensitive workloads (print, NTP, intranet), Azure App Service (public-facing, no internal integration), Azure Static Web Apps, Azure Container Instances (isolated, ephemeral), Sandbox subscriptions designed for experimentation, Proof-of-concept / pilot workloads with no sensitive data, Lab resource groups intended to be wiped/reset<br/><br/>**Storage:** Storage accounts hosting public or non-sensitive content, Azure Blob Storage for static asset delivery, Azure Archive storage (cold, no active credentials)<br/><br/>**Identity & Access:** App registrations with User.Read delegated only, Service principals with Reader on isolated resource group, Managed Identities with no RBAC assignments, Expired or disabled service principals, Guest user accounts with default permissions, Personal / sandbox resources with no privileged role assignments<br/><br/>**Networking:** Azure CDN endpoints (public content delivery), Azure DNS public zones (external name resolution only), Network Security Groups on isolated low-trust subnets, Azure Virtual WAN branches (read-only monitoring)<br/><br/>**Management & Governance:** Azure Cost Management (read-only), Azure Policy (read-only assignments), Azure Monitor (read-only, non-sensitive workloads), Azure Advisor (recommendations only), Azure Service Health alerts (read-only), Sandbox subscriptions for experimentation, Proof-of-concept and pilot resource groups with no sensitive data<br/><br/>**Hypervisor / Fabric:** Azure Sandbox / dev-test dedicated hosts, Non-production Azure Stack HCI clusters |



### Risk Index - How we prioritize scoring (customizable)?

**Disclaimer:** The risk scoring and prioritization model presented in this table is based on my personal assessment and general security best practices. The scoring methodology, severity levels, and criticality tiers are intended as a customizable reference framework. Actual risk prioritization may vary between organizations depending on their infrastructure, business impact, regulatory requirements, threat landscape, and risk tolerance.

[Download as CSV-file](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/SecurityInsight_RiskIndex.csv)

| Security<br />Domain | Category           | Sub<br />Category | ConfigurationId | Security<br />Severity | Risk<br />Consequence<br />Score_<br />Security<br />Severity | Criticality<br />TierLevel | Risk<br />Probability<br />Score_<br />Criticality<br />TierLevel | Comments                                                     |
| -------------------- | ------------------ | ----------------- | --------------- | ---------------------- | ------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
|                      |                    |                   |                 | Very High              | 4                                                            | Critical - tier  0         | 4                                                            |                                                              |
|                      |                    |                   |                 | Very High              | 4                                                            | High - tier 1              | 3                                                            |                                                              |
|                      |                    |                   |                 | Very High              | 4                                                            | Medium - tier 2            | 2                                                            |                                                              |
|                      |                    |                   |                 | Very High              | 4                                                            | Low - tier 3               | 1                                                            |                                                              |
|                      |                    |                   |                 | High                   | 3                                                            | Critical - tier  0         | 4                                                            |                                                              |
|                      |                    |                   |                 | High                   | 3                                                            | High - tier 1              | 3                                                            |                                                              |
|                      |                    |                   |                 | High                   | 3                                                            | Medium - tier 2            | 2                                                            |                                                              |
|                      |                    |                   |                 | High                   | 3                                                            | Low - tier 3               | 1                                                            |                                                              |
|                      |                    |                   |                 | Medium-High            | 2                                                            | Critical - tier  0         | 4                                                            |                                                              |
|                      |                    |                   |                 | Medium-High            | 2                                                            | High - tier 1              | 3                                                            |                                                              |
|                      |                    |                   |                 | Medium-High            | 2                                                            | Medium - tier 2            | 2                                                            |                                                              |
|                      |                    |                   |                 | Medium-High            | 2                                                            | Low - tier 3               | 1                                                            |                                                              |
|                      |                    |                   |                 | Medium                 | 1                                                            | Critical - tier  0         | 4                                                            |                                                              |
|                      |                    |                   |                 | Medium                 | 1                                                            | High - tier 1              | 3                                                            |                                                              |
|                      |                    |                   |                 | Medium                 | 1                                                            | Medium - tier 2            | 2                                                            |                                                              |
|                      |                    |                   |                 | Medium                 | 1                                                            | Low - tier 3               | 1                                                            |                                                              |
|                      |                    |                   |                 | Low                    | 1                                                            | Critical - tier  0         | 4                                                            |                                                              |
|                      |                    |                   |                 | Low                    | 1                                                            | High - tier 1              | 3                                                            |                                                              |
|                      |                    |                   |                 | Low                    | 1                                                            | Medium - tier 2            | 2                                                            |                                                              |
|                      |                    |                   |                 | Low                    | 1                                                            | Low - tier 3               | 1                                                            |                                                              |
| Endpoint             |                    |                   |                 | Very High              | 4                                                            | Critical - tier  0         | 4                                                            |                                                              |
| Endpoint             |                    |                   |                 | Very High              | 4                                                            | High - tier 1              | 3                                                            |                                                              |
| Endpoint             |                    |                   |                 | Very High              | 4                                                            | Medium - tier 2            | 2                                                            |                                                              |
| Endpoint             |                    |                   |                 | Very High              | 4                                                            | Low - tier 3               | 1                                                            |                                                              |
| Endpoint             |                    |                   |                 | High                   | 3                                                            | Critical - tier  0         | 4                                                            |                                                              |
| Endpoint             |                    |                   |                 | High                   | 3                                                            | High - tier 1              | 3                                                            |                                                              |
| Endpoint             |                    |                   |                 | High                   | 3                                                            | Medium - tier 2            | 2                                                            |                                                              |
| Endpoint             |                    |                   |                 | High                   | 3                                                            | Low - tier 3               | 1                                                            |                                                              |
| Endpoint             |                    |                   |                 | Medium-High            | 2                                                            | Critical - tier  0         | 4                                                            |                                                              |
| Endpoint             |                    |                   |                 | Medium-High            | 2                                                            | High - tier 1              | 3                                                            |                                                              |
| Endpoint             |                    |                   |                 | Medium-High            | 2                                                            | Medium - tier 2            | 2                                                            |                                                              |
| Endpoint             |                    |                   |                 | Medium-High            | 2                                                            | Low - tier 3               | 1                                                            |                                                              |
| Endpoint             |                    |                   |                 | Medium                 | 1                                                            | Critical - tier  0         | 4                                                            |                                                              |
| Endpoint             |                    |                   |                 | Medium                 | 1                                                            | High - tier 1              | 3                                                            |                                                              |
| Endpoint             |                    |                   |                 | Medium                 | 1                                                            | Medium - tier 2            | 2                                                            |                                                              |
| Endpoint             |                    |                   |                 | Medium                 | 1                                                            | Low - tier 3               | 1                                                            |                                                              |
| Endpoint             |                    |                   |                 | Medium                 | 1                                                            | Low - tier 3               | 1                                                            |                                                              |
| Endpoint             |                    |                   |                 | Medium                 | 1                                                            | Low - tier 3               | 1                                                            |                                                              |
| Endpoint             |                    |                   |                 | Medium                 | 1                                                            | Low - tier 3               | 1                                                            |                                                              |
| Endpoint             |                    |                   |                 | Low                    | 1                                                            | Critical - tier  0         | 4                                                            |                                                              |
| Endpoint             |                    |                   |                 | Low                    | 1                                                            | High - tier 1              | 3                                                            |                                                              |
| Endpoint             |                    |                   |                 | Low                    | 1                                                            | Medium - tier 2            | 2                                                            |                                                              |
| Endpoint             |                    |                   |                 | Low                    | 1                                                            | Low - tier 3               | 1                                                            |                                                              |
| Endpoint             | Security  controls |                   |                 | Very High              | 5                                                            | Critical - tier  0         | 4                                                            |                                                              |
| Endpoint             | Security controls  |                   |                 | Very High              | 5                                                            | High - tier 1              | 3                                                            |                                                              |
| Endpoint             | Security  controls |                   |                 | Very High              | 5                                                            | Medium - tier 2            | 2                                                            |                                                              |
| Endpoint             | Security controls  | Antivirus         | scid-2014       |                        | 5                                                            | Critical - tier 0          | 4                                                            |                                                              |
| Endpoint             | Security  controls | Antivirus         | scid-2014       |                        | 5                                                            | High - tier 1              | 3                                                            |                                                              |
| Endpoint             | Security controls  | Antivirus         | scid-2014       |                        | 5                                                            | Medium - tier 2            | 2                                                            |                                                              |
| Endpoint             | Security  controls | Antivirus         | scid-2014       |                        | 5                                                            | Low - tier 3               | 1                                                            |                                                              |
| Endpoint             | Security controls  | EDR               | scid-2002       | Very High              | 4                                                            | Critical - tier 0          | 4                                                            | Fix Microsoft Defender for Endpoint  impaired communications |
| Endpoint             | Security  controls | EDR               | scid-2002       | Very High              | 3                                                            | High - tier 1              | 3                                                            | Fix  Microsoft Defender for Endpoint impaired communications |
| Endpoint             | Security controls  | EDR               | scid-2002       | Very High              | 2                                                            | Medium - tier 2            | 2                                                            | Fix Microsoft Defender for Endpoint  impaired communications |
| Endpoint             | Security  controls | EDR               | scid-2002       | Very High              | 1                                                            | Low - tier 3               | 1                                                            | Fix  Microsoft Defender for Endpoint impaired communications |
| Endpoint             | Security controls  | EDR               | scid-2001       | Very High              | 2                                                            | Critical - tier 0          | 1                                                            | Fix Microsoft Defender for Endpoint  sensor data collection  |
| Endpoint             | Security  controls | EDR               | scid-2001       | Very High              | 2                                                            | High - tier 1              | 1                                                            | Fix  Microsoft Defender for Endpoint sensor data collection  |
| Endpoint             | Security controls  | EDR               | scid-2001       | Very High              | 2                                                            | Medium - tier 2            | 1                                                            | Fix Microsoft Defender for Endpoint  sensor data collection  |
| Endpoint             | Security  controls | EDR               | scid-2001       | Very High              | 2                                                            | Low - tier 3               | 1                                                            | Fix  Microsoft Defender for Endpoint sensor data collection  |
| Endpoint             | Security controls  | EDR               | scid-2000       | Very High              | 2                                                            | Critical - tier 0          | 1                                                            | Turn on Microsoft Defender for Endpoint  sensor              |
| Endpoint             | Security  controls | EDR               | scid-2000       | Very High              | 2                                                            | High - tier 1              | 1                                                            | Turn  on Microsoft Defender for Endpoint sensor              |
| Endpoint             | Security controls  | EDR               | scid-2000       | Very High              | 2                                                            | Medium - tier 2            | 1                                                            | Turn on Microsoft Defender for Endpoint  sensor              |
| Endpoint             | Security  controls | EDR               | scid-2000       | Very High              | 2                                                            | Low - tier 3               | 1                                                            | Turn  on Microsoft Defender for Endpoint sensor              |



## Reporting

The framework generates both summary and detailed reports.

**Summary reports** include number of findings per tier, overall risk levels, and configuration status.

**Detailed reports** include affected assets, vulnerability identifiers, and remediation guidance.

| File Name | Purpose |
| ------------------------------------------------------------ | ----------------------------------------------- |
| [Sample - RiskAnalysis_Summary_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/Sample%20-%20RiskAnalysis_Summary_Bucket.xlsx) | Sample summary output Excel file |
| [Sample - RiskAnalysis_Detailed_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/Sample%20-%20RiskAnalysis_Detailed_Bucket.xlsx) | Sample detailed output Excel file |
| [Sample mail - Summary report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/data/_samples/Sample%20mail%20-%20Summary%20report%20with%20AI%20summary.pdf) | Sample mail for Summary report with AI summary |
| [Sample mail - Detailed report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/data/_samples/Sample%20mail%20-%20Detailed%20report%20with%20AI%20summary.pdf) | Sample mail for Detailed report with AI summary |

------



# Governance and Compliance

SecurityInsight supports several important security frameworks.

### NIS2 Directive

NIS2 requires organizations to implement:

- risk-based cybersecurity management
- protection of critical infrastructure
- preventive security measures

SecurityInsight supports these requirements by prioritizing protection of the organization's most critical systems.

### CIS Critical Security Controls

The model aligns with several CIS controls, including:

- CIS Control 1 – Asset Inventory
- CIS Control 4 – Secure Configuration
- CIS Control 7 – Vulnerability Management
- CIS Control 12 – Network Infrastructure Management

------



# Operational Benefits

The risk-based model provides several advantages:

- **Clear security priorities** – Security teams can focus on the most critical risks.
- **Reduced operational noise** – Low-risk issues do not dominate remediation efforts.
- **Faster risk reduction** – The most dangerous vulnerabilities are addressed first.
- **Improved executive communication** – Risk scores translate technical findings into **business risk**.

------



# Future Opportunities

Potential future developments include:

- Automated attack path analysis — more queries
- Integration with ticketing and risk management platforms

------



# Transparency and Flexibility

A key strength of SecurityInsight is its **transparent and flexible architecture**.

Unlike many traditional security solutions where prioritization logic is embedded in proprietary algorithms, this model is designed to be **fully open and configurable**.

The architecture is based on widely available technologies, allowing organizations to understand and adjust the prioritization model according to their own needs.

Core components include:

- **Kusto Queries (KQL)** for security data analysis
- **PowerShell** for automation and report generation
- **CSV-based index files** defining risk scoring
- **Asset tagging** for classification of critical systems

This approach ensures that the model is **100% transparent and open**.

------



# Collaboration with Microsoft

The development of SecurityInsight is conducted in close dialogue with Microsoft.

The risk-based approach to prioritizing security recommendations — based on asset criticality and exposure analysis — has attracted significant interest within Microsoft's security organization.

**Morten Knudsen works closely with Microsoft, including Raviv Tamir, Corporate Vice President for Microsoft Defender, and his team.**

The goal of this collaboration is to explore how the principles behind SecurityInsight can influence the future development of the **Microsoft Defender platform**.

------



# Files Overview

> **v2 layout.** Engines live under `scripts/`, launchers under `launchers/<Engine>/`, and all data under
> `data/`. The `_Locked` suffix means "platform-curated, overwritten on every update"; the `_Custom` suffix
> means "your starter, preserved across updates."

## Asset Tagging

| File | Path in repo | Kind | Preserved on update? |
| --- | --- | --- | --- |
| Engine | `scripts/CriticalAssetTagging.ps1` | Platform | No — always overwritten |
| Launcher (VM) | `launchers/CriticalAssetTagging/launcher.community-vm.template.ps1` | Platform | No — always overwritten |
| Launcher (Azure host) | `launchers/CriticalAssetTagging/launcher.community-azure.template.ps1` | Platform | No — always overwritten |
| Credentials config (you edit) | `launchers/CriticalAssetTagging/LauncherConfig.ps1` | Customer | Never in repo (`.gitignore`) |
| Recommended tags | `data/SecurityInsight_CriticalAssetTagging_Locked.yaml` | Platform | No — always overwritten |
| Custom tags (you edit) | `data/SecurityInsight_CriticalAssetTagging_Custom.yaml` | Customer | **Yes** — install-once |
| Full reference sample | `data/_samples/SecurityInsight_CriticalAssetTagging_Custom.yaml` | Platform | No — always overwritten |

## Asset Tagging Maintenance (clean-up / remove orphaned tags)

| File | Path in repo | Kind |
| --- | --- | --- |
| Main-engine | `scripts/CriticalAssetTaggingMaintenance.ps1` | Platform |
| Launcher | `launchers/CriticalAssetTaggingMaintenance/launcher.community-*.template.ps1` | Platform |
| Fix-conflicts engine | `scripts/CriticalAssetTaggingMaintenance_FixConflictingTags.ps1` | Platform |
| Fix-conflicts launcher | `launchers/CriticalAssetTaggingMaintenance_FixConflictingTags/launcher.community-*.template.ps1` | Platform |

## Risk Analysis

| File | Path in repo | Kind | Preserved on update? |
| --- | --- | --- | --- |
| Engine | `scripts/SecurityInsight_RiskAnalysis.ps1` | Platform | No — always overwritten |
| Launcher (VM / Azure) | `launchers/SecurityInsight_RiskAnalysis/launcher.community-*.template.ps1` | Platform | No — always overwritten |
| Credentials config (you edit) | `launchers/SecurityInsight_RiskAnalysis/LauncherConfig.ps1` | Customer | Never in repo (`.gitignore`) |
| Recommended queries | `data/SecurityInsight_RiskAnalysis_Queries_Locked.yaml` | Platform | No — always overwritten |
| Custom queries (you edit) | `data/SecurityInsight_RiskAnalysis_Queries_Custom.yaml` | Customer | **Yes** — install-once |
| Risk priority index | `data/SecurityInsight_RiskIndex.csv` | Platform | No — always overwritten |
| Full reference queries sample | `data/_samples/SecurityInsight_RiskAnalysis_Queries_Custom.yaml` | Platform | No — always overwritten |

## Deploy OpenAI (optional, for AI summary)

| File | Path in repo | Kind |
| --- | --- | --- |
| Engine | `scripts/Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1` | Platform |
| Launcher — Primary | `launchers/Deploy_OpenAI_PAYG_Instance_SecurityInsights_Primary/launcher.community-*.template.ps1` | Platform |
| Launcher — Secondary | `launchers/Deploy_OpenAI_PAYG_Instance_SecurityInsights_Secondary/launcher.community-*.template.ps1` | Platform |

> **Why two Deploy_OpenAI launcher folders?** The same engine script runs against different subscriptions /
> regions (e.g. primary in Sweden Central, secondary in West Europe). Each launcher folder sets its own
> `SubscriptionId`, `ResourceGroupName`, `Location`, `AccountName`, `DeploymentName`. You edit the launcher's
> `LauncherConfig.ps1` for credentials, or modify the `launcher.override.ps1` (sibling of the template,
> also `.gitignore`'d) to swap any parameter at runtime without touching the template.

## Support file

| File Name | Purpose | Comment |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------ |
| [UpdateSecurityInsight.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/UpdateSecurityInsight.ps1) | Update Engine<br />Backup local files + Update files from [Github repo](https://github.com/KnudsenMorten/SecurityInsight) | Can be modified to your needs |
| [Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1) | Deploy OpenAI PAYG instance (optional)<br />Used for AI summary based on context from risk analysis | Must be modified to your needs |

## Sample Output files

| File Name | Purpose |
| ------------------------------------------------------------ | ----------------------------------------------- |
| [Sample mail - Detailed report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/data/_samples/Sample%20mail%20-%20Detailed%20report%20with%20AI%20summary.pdf) | Sample mail for Detailed report with AI summary |
| [Sample - RiskAnalysis_Detailed_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/blob/main/data/_samples/Sample%20-%20RiskAnalysis_Detailed_Bucket.xlsx) | Sample detailed output Excel file |
| [Sample mail - Summary report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/data/_samples/Sample%20mail%20-%20Summary%20report%20with%20AI%20summary.pdf) | Sample mail for Summary report with AI summary |
| [Sample - RiskAnalysis_Summary_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/blob/main/data/_samples/Sample%20-%20RiskAnalysis_Summary_Bucket.xlsx) | Sample summary output Excel file |

------



# High-level Overview of Implementation

> **ℹ️ Note on command syntax.** The steps below describe the *conceptual* flow (SPN creation,
> permissions, tagging approach, risk analysis). The **exact commands** in the code snippets are the
> legacy v1 form (`RunRiskAnalysis.ps1 -Summary` etc.) and are kept here as illustrative samples.
> For the **current v2 commands** — which launcher file to run, where `LauncherConfig.ps1` lives,
> how to pass parameters — see [📦 Installation & Running](#-installation--running) near the top
> of this document. The concepts (YAML structure, permissions, scheduling, AI integration) are
> unchanged; only the entry-point filenames differ.

Detailed steps for each phase are outlined in the sections below.

| Step | Actions |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| Step 1: **Prepare** SecurityInsight **files** on automation-server | 1.1. Download all files from Github and create folder on automation/batch-server<br /><br />1.2. Install necessary PowerShell modules on server |
| Step 2: **Onboard** Entra App registration | 2.1. Create Entra App registration (SPN) with Secret<br /><br />2.2. Delegate API permissions<br /><br />2.3. Delegate Azure permissions |
| Step 3: Set **Asset Tier Level** using tagging | 3.1. Adjust authentication details in launcher file<br /><br />3.2. Validate WhatIfMode<br /><br />3.3. Run Critical Asset launcher to tag recommended tags in PROD mode<br /><br />3.4. [PROD] Setup recurring job to run every x hours<br /><br />3.5. [TEST] Adjust custom YAML-file to tag resources in Test-mode<br /><br />3.6. [TEST] Run Critical Asset launcher to tag recommended tags in TEST mode<br /><br />3.7. [PROD] Promote queries to Prod-mode once validated |
| Step 4: Set **Asset Criticality Level** Classification | Step 4.1 – Setup Criticality Tier Level against Azure resources<br /><br />Step 4.2 – Setup Criticality Tier Level against Defender device resources<br /><br />Known gaps / missing capabilities |
| Step 5: Run **Risk Analysis** | Step 5.1. Adjust authentication + SMTP details in launcher file<br /><br />Step 5.2A. Run in SUMMARY mode (cmdline)<br /><br />Step 5.2B. Run in DETAILED mode (GUI/ISE)<br /><br />Step 5.2C. Run in DETAILED mode (cmdline)<br /><br />Step 5.2D. Run in DETAILED mode (GUI/ISE, alternative)<br /><br />Step 5.2E. Run with Custom Report Template (cmdline)<br /><br />Step 5.3A. Deploy OpenAI instance<br /><br />Step 5.3B. Run deployment script<br /><br />Step 5.3C. Enable AI summary in launcher file |

------



## Step 1: Prepare SecurityInsight files on automation-server

### 1.1. [Download all files from Github site](https://github.com/KnudsenMorten/SecurityInsight/archive/refs/heads/main.zip) and create folder on automation/batch-server

```
<drive>\SCRIPTS\SecurityInsight
```



### 1.2. Install necessary PowerShell modules on server (optional, as the script will also do this if missing)

```
Install-Module Az -Scope AllUsers -Force -AllowClobber
Install-Module Az.ResourceGraph -Scope AllUsers -Force -AllowClobber
Install-Module Microsoft.Graph -Scope AllUsers -Force -AllowClobber
Install-Module Microsoft.Graph.Security -Scope AllUsers -Force -AllowClobber
Install-Module MicrosoftGraphPS -Scope AllUsers -Force -AllowClobber
Install-Module ImportExcel -Scope AllUsers -Force -AllowClobber
Install-Module powershell-yaml -Scope AllUsers -Force -AllowClobber
```

------



## Step 2: Onboarding of Entra App registration - to be used with SecurityInsight

### 2.1. Create Entra App registration (SPN) and set Secret (note it down!)

By default, authentication is done with a Secret.

Feel free to adjust the login in the launcher files to store credentials in Key Vault, use a certificate, etc.

### 2.2. Delegate API permissions to Entra App SPN

Add the API permissions below — found under **APIs my organization uses**. Remember to **Grant Admin Consent**.

```
Microsoft Threat Protection -> AdvancedHunting.Read.All
Microsoft Graph -> ThreatHunting.Read.All
WindowsDefenderATP -> Machine.ReadWrite.All
```

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/EntraApp-API-Permissions.png)



### 2.3. Delegate 'Tag Contributor' and 'Reader' permissions in Azure to Entra App SPN on Tenant Root-level

This ensures the ability to tag all Azure resources and run Azure Resource Graph queries.

```
Tag Contributor (least privilege)
Reader (least privilege)
```

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/EntraApp-Azure-Permissions.png)

------



## Step 3: Setting Asset Tier Level using tagging

Assets are automatically classified using tagging rules based on system roles. Examples include:

- Domain Controllers
- Entra synchronization services
- Employee devices
- IoT devices

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/MDE-Asset-Tag-Recommended-Samples.png)

Asset tagging uses a tagging engine that queries resources against **Defender Graph** or **Azure Resource Graph** using **Kusto KQL**.

Each query includes the Asset Tag to set. Queries return only deltas — assets that are missing a tag. The tagging engine runs on a defined schedule, such as every 4 hours.

### Structure of query in YAML-file

| Property | Purpose |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| AssetTagName | Asset tag name |
| Mode | Implementation scope <br />(can be defined in launcher or commandline)<br /><br />Supported values:<br />Prod<br />Test |
| QueryEngine | Select query engine<br /><br />Supported values:<br />DefenderGraph = ExposureGraph<br />AzureResourceGraph = Azure Resource Graph |
| Query structure<br /><br />Step 1: Scoping - what to find?<br />Step 2: Get existing Tags "as-is"<br />Step 3: Define Value for tag to set "to-be"<br />Step 4: Write resources<br />Step 5: Filter resources to show only resources in scope with missing tag (delta) | Query the Graph<br /><br />AssetTagType supported values: <br />AssetTier--SI = shows asset is in-scope with tier-info<br />Asset--Excluded--SI = shows asset must be excluded<br /><br />AssetTag = any value that makes the asset unique<br /><br />AssetTierLevel = 0,1,2,3 |

### Asset Tagging files

| File Name | Purpose | Continues Updates via UpdateSecurityInsight-script |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| [RunCriticalAssetTagging.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/RunCriticalAssetTagging.ps1) | Engine Launcher for Asset Tagging<br />Includes parameters for starting asset tagging engine | No (custom file) |
| [CriticalAssetTagging.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/CriticalAssetTagging.ps1) | Main Engine for Asset Tagging<br />Uses YAML-files as data repo | Yes |
| [SecurityInsight_CriticalAssetTagging_Custom.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_CriticalAssetTagging_Custom.yaml) | Data file (custom tags)<br />Kusto queries against graph-engines | No (custom asset tags) |
| [SecurityInsight_CriticalAssetTagging_Locked.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_CriticalAssetTagging_Locked.yaml) | Data file (recommended tags)<br />Kusto queries against graph-engines | Yes |
| RunCriticalAssetTaggingMaintenance_FixConflictingTags.ps1 | Engine launcher — removes tags on Defender objects where multiple tiers have been applied. Retains the highest tier and removes the others. | No |
| CriticalAssetTaggingMaintenance_FixConflictingTags.ps1 | Main engine — removes conflicting tags on Defender objects | No |



### Step 3.1. Adjust the authentication details in launcher file, RunCriticalAssetTagging.ps1 (SpnTenantId, SpnClientId, SpnClientSecret)

> **Note:** Avoid storing secrets directly in files in production — this is provided as a sample only.

```
If (-not $AutomationFramework) {

    $global:SpnTenantId         = "<Your TenantId>"     # override per your SPN tenant if different
    $global:SpnClientId         = "<APP/CLIENT ID GUID>"
    $global:SpnClientSecret     = "<CLIENT SECRET VALUE>"
}
```



### Step 3.2. Adjust the WhatIfMode to $true, if you are only testing. Otherwise leave it as $false to set the tags

```
$WhatIfMode                  = $false
```



### Step 3.3. [PROD]  Run Critical Asset launcher to tag recommended tags in PROD mode

```
RunCriticalAssetTagging.ps1 -SCOPE PROD

Sample:
<Drive>:\SCRIPTS\SecurityInsights\RunCriticalAssetTagging.ps1 -SCOPE PROD
```

You will now get the following tags applied, based on the data file **SecurityInsight_CriticalAssetTagging_Locked.yaml**:

- AzPlatformManagementResources--tier0--SI
- AzPlatformManagementResources--tier0--SI
- DomainControllerDNS--tier0--SI
- ADCertificateService--tier0--SI
- EntraSyncService--tier0--SI
- EmployeeWorkstations--tier2--SI
- EmployeeMobile--tier2--SI
- IoT--tier3--SI

> **Important:** The tagging engine in PROD mode aggregates queries from both data files:
> - SecurityInsight_CriticalAssetTagging_Custom.yaml
> - SecurityInsight_CriticalAssetTagging_Locked.yaml

#### Example of recommended query to detect Sentinel resources

```
  - AssetTagName: AzPlatformManagementResources--tier0--SI
    Mode: Prod
    QueryEngine: AzureResourceGraph
    Query:
      - |
        resourcecontainers
        | where type == "microsoft.resources/subscriptions"
        | join kind=inner (
            resources
            | where type == "microsoft.operationsmanagement/solutions"
            | where name startswith "SecurityInsights("
            | project subscriptionId
            | distinct subscriptionId
        ) on subscriptionId
        | extend
            Tag_AssetTier = tostring(tags["AssetTier--SI"])
        | extend
            AssetTagType   = "AssetTier--SI",
            AssetTag       = "AzPlatformManagementSub",
            AssetTierLevel = 0
        | extend
            AssetTagName = strcat(AssetTag, "--tier", tostring(AssetTierLevel), "--SI")
        | project
            subscriptionId,
            subscriptionName = name,
            Tag_AssetTier,
            AssetTagType,
            AssetTag,
            AssetTierLevel,
            AssetTagName,
            id
        | order by subscriptionId asc
        | where Tag_AssetTier != AssetTagName
```

#### Example of recommended query to detect Domain controller resources

```
  - AssetTagName: DomainControllerDNS--tier0--SI
    Mode: Prod
    QueryEngine: DefenderGraph
    Query:
      - |
        ExposureGraphNodes

        // Filter
        | where NodeLabel has "device"
           or NodeLabel has "microsoft.compute/virtualmachines"
           or NodeLabel has "microsoft.hybridcompute/machines"

        | extend rawData = todynamic(NodeProperties).rawData
        | where tobool(rawData.isExcluded) == false
        | where tostring(rawData.deviceType) == "Server"
        | where tolower(tostring(rawData.onboardingStatus)) == "onboarded"
        | project NodeId, NodeName, NodeLabel, rawData, EntityIds
        | extend
            confidenceHigh = iff(isnull(rawData.criticalityConfidenceHigh), dynamic([]), todynamic(rawData.criticalityConfidenceHigh)),
            confidenceLow  = iff(isnull(rawData.criticalityConfidenceLow),  dynamic([]), todynamic(rawData.criticalityConfidenceLow))
        | extend
            DetectedRoles  = strcat_array(array_concat(confidenceHigh, confidenceLow), ";"),
            osPlatform     = tostring(rawData.osPlatform),
            osVersion      = tostring(rawData.osVersion),
            onboardingStatus = tostring(rawData.onboardingStatus)

        | where DetectedRoles has "DomainController"
            or DetectedRoles has "Dns"

        // Output Required Columns
        | extend
            deviceManualTags = iff(isnull(rawData.deviceManualTags), dynamic([]), todynamic(rawData.deviceManualTags)),
            deviceDynamicTags = iff(isnull(rawData.deviceDynamicTags), dynamic([]), todynamic(rawData.deviceDynamicTags)),
            tags = iff(isnull(rawData.tags.tags), dynamic([]), todynamic(rawData.tags.tags))
        | extend
             AssetTags  = strcat_array(array_concat(deviceManualTags, deviceDynamicTags), ";")
        | extend entityIds_dyn = todynamic(EntityIds)
        | mv-apply e = entityIds_dyn on (
            summarize
                DeviceInventoryId = anyif(tostring(e.id), tostring(e.type) == "DeviceInventoryId"),
                SenseDeviceId     = anyif(tostring(e.id), tostring(e.type) == "SenseDeviceId"),
                AzureResourceId   = make_list_if(tostring(e.id), tostring(e.type) == "AzureResourceId")
        )
        | extend AzureResourceId = strcat_array(AzureResourceId, ";")

        // Tagging BEGIN ---------------
        | extend
            AssetTagType   = "AssetTier--SI",
            AssetTag       = "DomainControllerDNS",
            AssetTierLevel = 0
        | extend    
            AssetTagName   = strcat(AssetTag, "--tier", tostring(AssetTierLevel), "--SI")
        // Tagging END -----------------

        // Show only Assets in the output, which doesn't have the tag
        | extend AssetTagsArray = iff(isempty(AssetTags), dynamic([]), split(AssetTags, ";"))
        | where array_index_of(AssetTagsArray, AssetTagName) == -1
```

#### Example of recommended query to detect Employee Workstations

```
- AssetTagName: EmployeeWorkstations--tier2--SI
    Mode: Prod
    QueryEngine: DefenderGraph
    Query:
      - |
        ExposureGraphNodes

        // Filter
        | where NodeLabel has "device"
            or NodeLabel has "microsoft.compute/virtualmachines"
            or NodeLabel has "microsoft.hybridcompute/machines"
        | extend rawData = todynamic(NodeProperties).rawData
        | where tobool(rawData.isExcluded) == false
        | where tostring(rawData.deviceType) == "Workstation"
        | where tolower(tostring(rawData.onboardingStatus)) == "onboarded"
        | project NodeId, NodeName, NodeLabel, rawData, EntityIds

        // Output Required Columns
        | extend
            deviceManualTags  = iff(isnull(rawData.deviceManualTags),  dynamic([]), todynamic(rawData.deviceManualTags)),
            deviceDynamicTags = iff(isnull(rawData.deviceDynamicTags), dynamic([]), todynamic(rawData.deviceDynamicTags)),
            tags              = iff(isnull(rawData.tags.tags),         dynamic([]), todynamic(rawData.tags.tags))
        | extend
            AssetTags = strcat_array(array_concat(deviceManualTags, deviceDynamicTags), ";")
        | extend entityIds_dyn = todynamic(EntityIds)
        | mv-apply e = entityIds_dyn on (
            summarize
                DeviceInventoryId = anyif(tostring(e.id), tostring(e.type) == "DeviceInventoryId"),
                SenseDeviceId     = anyif(tostring(e.id), tostring(e.type) == "SenseDeviceId"),
                AzureResourceId   = make_list_if(tostring(e.id), tostring(e.type) == "AzureResourceId")
        )
        | extend AzureResourceId = strcat_array(AzureResourceId, ";")

        // Tagging BEGIN ---------------
        | extend
            AssetTagType   = "AssetTier--SI",
            AssetTag       = "EmployeeWorkstations",
            AssetTierLevel = 2
        | extend
            AssetTagName = strcat(AssetTag, "--tier", tostring(AssetTierLevel), "--SI")
        // Tagging END -----------------

        // Show only assets that don't already have the tag
        | extend AssetTagsArray = iff(isempty(AssetTags), dynamic([]), split(AssetTags, ";"))

        // Exclude devices already marked Tier 0 or Tier 1 (--tier0--SI & --tier1--SI)
        | where AssetTags !has "--tier0--SI"
        | where AssetTags !has "--tier1--SI"

        // Only assets missing the intended Tier 1 tag
        | where array_index_of(AssetTagsArray, AssetTagName) == -1
```



### Step 3.4. [PROD]  Setup Recurring job to run every x hours using task scheduler or 3rd party software like VisualCron. This job should only run the queries that have been tested, validated, and promoted to PROD status.

```
RunCriticalAssetTagging.ps1 -SCOPE PROD

Sample:
<Drive>:\SCRIPTS\SecurityInsights\RunCriticalAssetTagging.ps1 -SCOPE PROD
```



### Step 3.5. [TEST]  Adjust custom yaml-file to tag resources in Test-mode

You can modify sample TEST-queries and fine-tune them to match your environment.

Fine-tuning often requires adjustment based on **naming conventions (Defender)**, **management group naming (Azure)**, or **IP subnets (backbone/network)**. Examples:

| AssetTagName | What needs to be changed in Query? |
| ------------------------------------------- | ------------------------------------------------------------ |
| AzHubPlatformManagementSub--tier0--SI | Name of management group?<br /><br /> where properties.managementGroupAncestorsChain has "mg-platform-management" |
| AzHubPlatformManagementResources--tier0--SI | Name of management group?<br /><br /> where properties.managementGroupAncestorsChain has "mg-platform-management" |
| AzHubPlatformSecuritySub--tier0--SI | Name of management group?<br /><br /> where properties.managementGroupAncestorsChain has "mg-platform-security" |
| AzHubPlatformSecurityResources--tier0--SI | Name of management group?<br /><br /> where properties.managementGroupAncestorsChain has "mg-platform-security" |

#### Testing Queries - Azure Resource Graph

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/TestingQueries-Azure.png)

#### Testing Queries - Defender

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/TestingQueries-Defender.png)

#### Defender: How can I validate & Show all tagged resources when I test?

Find this line

```
| where array_index_of(AssetTagsArray, AssetTagName) == -1
```

Change to (add // in front)

```
// | where array_index_of(AssetTagsArray, AssetTagName) == -1
```

#### Azure: How can I validate & Show all tagged resources when I test?

Find this line

```
| where Tag_AssetTier != AssetTagName
```

Change to (add // in front)

```
// | where Tag_AssetTier != AssetTagName
```



### Step 3.6. [TEST]  Run Critical Asset launcher to tag recommended tags in TEST mode

```
RunCriticalAssetTagging.ps1 -SCOPE TEST

Sample:
<Drive>:\SCRIPTS\SecurityInsights\RunCriticalAssetTagging.ps1 -SCOPE TEST
```

You will now get the following tags applied, based on the data file **SecurityInsight_CriticalAssetTagging_Custom.yaml**:

- AzHubPlatformManagementSub--tier0--SI
- AzHubPlatformManagementResources--tier0--SI
- AzHubPlatformSecuritySub--tier0--SI
- AzHubPlatformSecurityResources--tier0--SI
- AzLZDatacenterSub--tier0--SI
- AutomationServer--tier0--SI
- ServerBusinessServices--tier1--SI
- PAWDevices--tier0--SI
- Network_Backbone_Switch--tier0--SI
- Network_Backbone_Router--tier0--SI
- Network_Backbone_Management--tier0--SI
- Network_WLANAccessPoint--tier2--SI
- Temp-Client-Devices--excluded--SI  ← This query is special — it finds resources that should be excluded (special tag)

This process typically takes several iterations and involves multiple teams and documentation, including naming conventions, IP plans, and business system overviews.

#### Example of custom query for backbone network switch

```
  - AssetTagName: Network_Backbone_Switch--tier0--SI
    Mode: Test
    QueryEngine: DefenderGraph
    Query:
      - |
        let TargetSubnet = "192.168.1.0/24";

        let SwitchNodes =
            ExposureGraphNodes
            // Filter
            | where NodeLabel has "device"
            | extend rawData = todynamic(NodeProperties).rawData
            | where tobool(rawData.isExcluded) == false
            | where tostring(rawData.deviceSubtype) == "Switch"
            | project NodeId, NodeName, NodeLabel, rawData, EntityIds

            // Output Required Columns
            | extend
                deviceManualTags  = iff(isnull(rawData.deviceManualTags),  dynamic([]), todynamic(rawData.deviceManualTags)),
                deviceDynamicTags = iff(isnull(rawData.deviceDynamicTags), dynamic([]), todynamic(rawData.deviceDynamicTags)),
                tags              = iff(isnull(rawData.tags.tags),         dynamic([]), todynamic(rawData.tags.tags))
            | extend
                AssetTags = strcat_array(array_concat(deviceManualTags, deviceDynamicTags), ";")

            // Extract device IDs
            | extend entityIds_dyn = todynamic(EntityIds)
            | mv-apply e = entityIds_dyn on (
                summarize
                    DeviceInventoryId = anyif(tostring(e.id), tostring(e.type) == "DeviceInventoryId"),
                    SenseDeviceId     = anyif(tostring(e.id), tostring(e.type) == "SenseDeviceId"),
                    AzureResourceId   = make_list_if(tostring(e.id), tostring(e.type) == "AzureResourceId")
            )
            | extend AzureResourceId = strcat_array(AzureResourceId, ";")

            // Normalize DeviceId for join
            | extend DeviceId = DeviceInventoryId
            | where isnotempty(DeviceId)

            // Tagging logic
            | extend
                AssetTagType   = "AssetTier--SI",
                AssetTag       = "Network_Backbone_Switch",
                AssetTierLevel = 0
            | extend
                AssetTagName = strcat(AssetTag, "--tier", tostring(AssetTierLevel), "--SI");

        SwitchNodes
        | join kind=inner (
            DeviceNetworkInfo
            | mv-expand ip = IPAddresses
            | extend
                IPAddress    = tostring(ip.IPAddress),
                AddressType  = tostring(ip.AddressType),
                SubnetPrefix = tostring(ip.SubnetPrefix)
            | where isnotempty(IPAddress)
            | where AddressType =~ "Private"
            | where ipv4_is_in_range(IPAddress, TargetSubnet)
            | project DeviceId, DeviceName, NetworkAdapterName, IPAddress, AddressType, SubnetPrefix
        ) on DeviceId

        | project
            NodeName,
            NodeLabel,
            DeviceId,
            DeviceInventoryId = DeviceId,
            IPAddress,
            NetworkAdapterName,
            AssetTagName,
            AssetTags
        | distinct NodeName, NodeLabel, DeviceId, DeviceInventoryId, IPAddress, NetworkAdapterName, AssetTagName, AssetTags

        // Show only assets that don't already have the tag
        | extend AssetTagsArray = iff(isempty(AssetTags), dynamic([]), split(AssetTags, ";"))

        // Only assets missing the intended Tier 1 tag
        | where array_index_of(AssetTagsArray, AssetTagName) == -1
```

#### Example of custom query to tag temporary autopilot objects that should be excluded, as they will be renamed

```
  - AssetTagName: Temp-Client-Devices--excluded--SI
    Mode: Prod
    QueryEngine: DefenderGraph
    Query:
      - |
        ExposureGraphNodes

        // Filter
        | where NodeLabel has "device"
            or NodeLabel has "microsoft.compute/virtualmachines"
            or NodeLabel has "microsoft.hybridcompute/machines"
        | extend rawData = todynamic(NodeProperties).rawData
        | where tobool(rawData.isExcluded) == false
        | where tostring(rawData.deviceType) == "Workstation"
        | where NodeName startswith "fvf-"
        | where NodeName !has "cloud"
        | project NodeId, NodeName, NodeLabel, rawData, EntityIds

        // Output Required Columns
        | extend
            deviceManualTags  = iff(isnull(rawData.deviceManualTags),  dynamic([]), todynamic(rawData.deviceManualTags)),
            deviceDynamicTags = iff(isnull(rawData.deviceDynamicTags), dynamic([]), todynamic(rawData.deviceDynamicTags)),
            tags              = iff(isnull(rawData.tags.tags),         dynamic([]), todynamic(rawData.tags.tags))
        | extend
            AssetTags = strcat_array(array_concat(deviceManualTags, deviceDynamicTags), ";")
        | extend entityIds_dyn = todynamic(EntityIds)
        | mv-apply e = entityIds_dyn on (
            summarize
                DeviceInventoryId = anyif(tostring(e.id), tostring(e.type) == "DeviceInventoryId"),
                SenseDeviceId     = anyif(tostring(e.id), tostring(e.type) == "SenseDeviceId"),
                AzureResourceId   = make_list_if(tostring(e.id), tostring(e.type) == "AzureResourceId")
        )
        | extend AzureResourceId = strcat_array(AzureResourceId, ";")

        // Tagging BEGIN ---------------
        | extend
            AssetTagType   = "Asset--Excluded--SI",
            AssetTag       = "Temp-Client-Devices"
        | extend
            AssetTagName = strcat(AssetTag, "--Excluded--SI")
        // Tagging END -----------------

        // Show only assets that don't already have the tag
        | extend AssetTagsArray = iff(isempty(AssetTags), dynamic([]), split(AssetTags, ";"))

        // Only assets missing the intended Tier 1 tag
        | where array_index_of(AssetTagsArray, AssetTagName) == -1
```



### Step 3.7. [PROD]  Adjust queries to Prod-mode once happy. Now they will be included in the recurring job

```
    Mode: Test
```

Change to

```
    Mode: Prod
```

------



## Step 4: Setting Asset Criticality Level Classification

Not all systems in an organization are equally important. Assets are classified into **4 criticality tiers**.

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/MDE-Criticality-Sample.png)

Not all resource types in Defender Critical Asset Management support the Criticality Tier natively. Tags are used in the risk model when native criticality data is not available.

| Criticality Level (Defender) | Tier | Category | Examples of systems |
| ------------------------------------ | -------- | ------------------------- | ------------------------------------------------------------ |
| Critical / Very high | Tier-0 | Identity Control | Domain Controllers, Entra / Azure AD Sync, core authentication systems |
| High | Tier-1 | Privileged Infrastructure | Infrastructure servers, authentication systems, management platforms |
| Medium | Tier-2 | Business Systems | Employee workstations, application servers, collaboration systems |
| Low | Tier-3 | Low-Trust Systems | IoT devices, testing environments and specialized systems |

Assets are classified using two methods in Defender Critical Asset Management:

- **Automatic classification** — predefined classifications
- **Custom classification** — using tags in Defender and Azure

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/CriticalityLevel-Defender-overview.png)

### Custom Classification Examples — customize to your needs

| Name | Criticality Level | Query builder | Query |
| ---------------------------------------- | ----------------- | -------------- | ------------------------------------------------------------ |
| EmployeeMobile--tier2--SI | Medium - tier 2 | Device | Tags contains EmployeeMobile--tier2--SI |
| AutomationServer--tier0--SI | Very high - tier0 | Device | Tags contains AutomationServer--tier0--SI |
| Network_Backbone_Switch--tier0--SI | Very high - tier0 | Device | Tags contains Network_Backbone_Switch--tier0--SI |
| Network_Backbone_Router--tier0--SI | Very high - tier0 | Device | Tags contains Network_Backbone_Router--tier0--SI |
| IoT--tier3--SI | Low - tier 3 | Device | Tags contains IoT--tier3--SI |
| EmployeeWorkstations--tier2--SI | Medium - tier 2 | Device | Tags contains EmployeeWorkstations--tier2--SI |
| ServerBusinessServices--tier1--SI | High - tier 1 | Device | Tags contains ServerBusinessServices--tier1--SI |
| PAWDevices--tier0--SI | Very high - tier0 | Device | Tags contains PAWDevices--tier0--SI |
| Network_WLANAccessPoint--tier2--SI | Medium - tier 2 | Device | Tags contains Network_WLANAccessPoint--tier2--SI |
| Network_Backbone_Management--tier0--SI | Very high - tier0 | Device | Tags contains Network_Backbone_Management--tier0--SI |
| ADCertificateService--tier0--SI | Very high - tier0 | Device | Tags contains ADCertificateService--tier0--SI |
| EntraSyncService--tier0--SI | Very high - tier0 | Device | Tags contains EntraSyncService--tier0--SI |
| DomainControllerDNS--tier0--SI | Very high - tier0 | Device | Tags contains DomainControllerDNS--tier0--SI |
| AzPlatformManagementResources--tier0--SI | Very high - tier0 | Cloud resource | Resources Tags equals assetTier--SI = AzPlatformManagementResources--tier0--SI |
| AzPlatformManagementSub--tier0--SI | Very high - tier0 | Cloud resource | Resources Tags equals assetTier--SI = AzPlatformManagementSub--tier0--SI |
| Tier-0 Critical Users | Very high - tier0 | Identity | OR:<br />Email Address contains -L0-T0-<br />Email Address contains mok@2linkit.net |
| Tier-1 Identity Admin Account | High - tier 1 | Identity | AND:<br />Email Address starts with Admin-<br />Email Address does not end with -L0-T0-ID@2linkit.net<br />Email Address does not end with -L0-T0-AD@2linkit.net |
| Tier-1 Identity Service Accounts | High - tier 1 | Identity | AND:<br />Email Address starts with SVC- |
| Tier-2 Identity Users | Medium - tier 2 | Identity | AND:<br />Email Address does not end with mok@2linkit.net<br />Email Address does not start with Admin-<br />Email Address does not start with BGA-<br />Email Address does not start with MSOL<br />Email Address does not start with Administrator<br />Email Address does not start with AAD<br />Email Address does not start with gMSA<br />Email Address does not start with SVC-<br />Account Name does not start with Administrator<br />Account Name does not start with gMSA<br />Account Name does not start with MSOL<br />Account Name does not start with AAD<br />Account Name does not start with krbtgt<br />Account Name does not start with Guest<br />Account Name does not start with On-Premises Directory Synchronization Service Account<br />Account Name does not start with svc |

### Step 4.1 - How to setup Criticality Tier Level against Azure resources?

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/CriticalityLevel-Defender-Azure-tags.png)

> **Note:** Adding a new Azure Tag takes between 24–48 hours to appear in Defender Critical Asset Management due to sync delays.

### Step 4.2 - How to setup Criticality Tier Level against Defender device resources?

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/docs/Images/CriticalityLevel-Defender-MDE-tags.png)

### What am I missing in Critical Asset Management?

| Area | What is missing? |
| ------------------------- | ------------------------------------------------------------ |
| Critical Asset Management | Ability to run a Kusto query instead of having to choose static fields. Much more efficient and would overcome limitations where tables need to be correlated.<br /><br />Many fields are missing, such as device roles and internal IP address. |
| Critical Asset Management | API for onboarding of custom classifications. Currently requires manual creation. |
| Device (custom query) | Internal IP Address is not an option |
| Identity (custom query) | Operator 'not contains' is missing.<br /><br />Impossible to write a query like: Find all Admins that start with Admin- AND don't contain "-T0-L0-id" |
| Identity (custom query) | extensionAttribute1-15 is missing.<br /><br />Many organizations tag users using extensionAttribute6 (Classification) = Internal_User, Service_Account or extensionAttribute7 (AuthenticationMethod) |

------



## Step 5: Run the Risk Analysis

The solution consists of three main components:

| Data collection (Input) | Analysis | Reporting (Output) |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------- |
| Microsoft Defender<br />Exposure Graph<br />Azure Resource Graph | Kusto queries<br />YAML report definitions<br />Risk score calculations | Excel reports<br />Summary Email |

## Files Overview (Risk Analysis)

| File Name | Purpose | Continues Updates via UpdateSecurityInsight-script |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| [RunSecurityInsight.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/RunSecurityInsight.ps1) | Engine Launcher<br />Includes parameters for starting risk analysis engine | No (custom file) |
| [SecurityInsight_RiskAnalysis.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskAnalysis.ps1) | Main Engine for Risk Analysis<br />Uses YAML-files as data repo<br />Uses RiskIndex-file to prioritize score | Yes |
| [SecurityInsight_RiskIndex.csv](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskIndex.csv) | Risk Index data file | No (*) (custom priority file) |
| [SecurityInsight_RiskAnalysis_Queries_Custom.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskAnalysis_Queries_Custom.yaml) | Report data file (custom queries)<br />Kusto queries against graph-engine | No (custom queries) |
| [SecurityInsight_RiskAnalysis_Queries_Locked.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskAnalysis_Queries_Locked.yaml) | Report data file (recommended queries)<br />Kusto queries against graph-engine | Yes |

(*) If you don't make custom changes to the RiskIndex file, you can add it to `UpdateSecurityInsight.ps1` to subscribe to recommended priorities.

### Step 5.1. Adjust the authentication + SMTP details in launcher file, RunSecurityInsight.ps1

> **Note:** Avoid storing secrets directly in files in production — this is provided as a sample only.

```
if (-not $global:AutomationFramework) {

    # SPN
    $global:SpnTenantId        = "<Your TenantId>"     # override per your SPN tenant if different
    $global:SpnClientId        = "<APP/CLIENT ID GUID>"
    $global:SpnClientSecret    = "<CLIENT SECRET VALUE>"

    # Email Notifications
    $global:SendMail           = $false # true/false
    $global:MailTo             = @()    # array of recipients
    $global:Mail_SendAnonymous = $false # $true = anonymous login against SMTP server
    $global:SMTPUser           = "<SMTP from address>"   # Default FROM address
    $global:SmtpServer         = "<SMTP server>"
    $global:SMTPPort           = 587
    $global:SMTP_UseSSL        = $true  # or $false

    if (-not $global:Mail_SendAnonymous) {

        # Consider using an Azure Key Vault to retrieve credentials securely
        $global:SmtpUsername   = "<SMTP username>"
        $global:SmtpPassword   = "<SMTP password>"

        $SecurePassword = ConvertTo-SecureString $global:SmtpPassword -AsPlainText -Force
        $global:SecureCredentialsSMTP = New-Object System.Management.Automation.PSCredential (
            $global:SmtpUsername,
            $SecurePassword
        )
    }
}
```

### Step 5.2A.  Run Risk Analysis launcher in SUMMARY mode (cmdline)

```
RunRiskAnalysis.ps1 -Summary

Sample:
<Drive>:\SCRIPTS\SecurityInsights\RunRiskAnalysis.ps1 -Summary
```

### Step 5.2B.  Run Risk Analysis launcher in DETAILED mode (GUI/ISE mode, alternative)

```
Verify / Adjust this line
$ReportTemplate_Default      = 'RiskAnalysis_Summary_Bucket'
```

### Step 5.2C.  Run Risk Analysis launcher in DETAILED mode (cmdline)

```
RunRiskAnalysis.ps1 -Detailed

Sample:
<Drive>:\SCRIPTS\SecurityInsights\RunRiskAnalysis.ps1 -Detailed
```

### Step 5.2D.  Run Risk Analysis launcher in DETAILED mode (GUI/ISE mode, alternative)

```
Verify / Adjust this line
$ReportTemplate_Default      = 'RiskAnalysis_Detailed_Bucket'
```

### Step 5.2E.  Run Risk Analysis launcher for Custom Report Template (cmdline)

```
RunRiskAnalysis.ps1 -Detailed -ReportTemplate "RiskAnalysis_Detailed_Bucket_Test"

Sample:
<Drive>:\SCRIPTS\SecurityInsights\RunRiskAnalysis.ps1 -Detailed
```

### Step 5.3A. Deploy OpenAI instance to enable AI Support, Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1

Adjust the parameters: SubscriptionId, ResourceGroupName, Location, AccountName, DeploymentName

```
$ScriptDefaults = @{
    SubscriptionId      = "xxxxxxxxx"
    ResourceGroupName   = "rg-security-insight"
    Location            = "swedencentral"
    AccountName         = "oai-xxxxx-security-insight"
    DeploymentName      = "oai-xxxxx-security-insight"

    # Preferred default (may not be supported; script will try others)
    ModelName           = "gpt-4.1-mini"
    ModelVersion        = "latest"

    Capacity            = 100   # script uses this as "sku.capacity" for the deployment PUT
    PublicNetworkAccess = "Enabled"
    WaitForAccountReady = $true

    DeploymentSkuOrder  = @("GlobalStandard")

    WriteModelDumps     = $true
}
```

### Step 5.3B. Run Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1 to deploy AI instance

```
Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1

Sample:
<Drive>:\SCRIPTS\SecurityInsights\Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1
```

### Step 5.3C. Adjust the Risk Analysis launcher file to enable AI summary support (RunSecurityInsight.ps1)

Find the value

```
$BuildSummaryByAI_Default    = $false # $true = enable AI summary integration (require OpenAI PAYG instance deployment)
```

Change to

```
$BuildSummaryByAI_Default    = $true
```

Adjust the AI section with the details from step 5.3B

```
if ($global:BuildSummaryByAI) {

    $global:OpenAI_apiKey              = "<API Key>"     # sample: "xxxxxxxxxxxxxxxxxxxxx"
    $global:OpenAI_endpoint            = "<URL>"     # sample: "https://xxxxx.openai.azure.com"
    $global:OpenAI_deployment          = "<Open AI Deployment Name>"     # sample: "security-insight"
    $global:OpenAI_apiVersion          = "<OPEN AI Deployment API version for REST api>"     # sample: "2025-01-01-preview"
    $global:OpenAI_MaxTokensPerRequest = 16384  # Recommended: 16384 - Azure OpenAI max_tokens default - modify to your needs

  $global:AI_MaxTokensPerRequest = [int]$global:OpenAI_MaxTokensPerRequest
  Write-Host ("[LAUNCHER] AI Max Tokens Per Request: {0}" -f $global:AI_MaxTokensPerRequest)
}
```

### Example of Query - Device_Missing_CVEs_Summary_BucketFilter

```
    - ReportName: Device_Missing_CVEs_Summary_BucketFilter
      ReportPurpose: This report highlights overdue endpoint CVEs older than 40 days, excluding out-of-scope assets, and prioritizes
        them using asset criticality, tag-based tiering, and exploit and exposure risk factors to focus remediation on the most
        critical and likely exploitable vulnerabilities.
      SecurityDomain: Endpoint
      CategoryInputName: Category
      SubcategoryInputName: Subcategory
      ConfigurationIdInputName: ConfigurationId
      SecuritySeverityInputName: SecuritySeverity
      CriticalityTierLevelInputName: CriticalityTierLevel
      RiskConsequenceScoreOutputName: RiskConsequenceScore
      RiskProbabilityScoreOutputName: RiskProbablityScore
      RiskScoreOutputName: RiskScoreTotal
      CriticalityTierLevelScope:
      - Critical - tier 0
      - High - tier 1
      - Medium - tier 2
      - Low - tier 3
      SecuritySeverityScope:
      - Very High
      - High
      - Medium-High
      - Medium
      - Low
      OutputPropertyOrder:
      - SecurityDomain
      - Category
      - Subcategory
      - ConfigurationName
      - ConfigurationId
      - Impact
      - SecuritySeverity
      - CriticalityTier
      - CriticalityTierLevel
      - RiskFactor_Consequence
      - RiskFactor_Probability
      - RiskFactor_Probability_Detailed
      - RiskFactor_Probability_DetailedScore
      - RiskConsequenceScore
      - RiskProbablityScore
      - RiskScoreTotal
      - AssetCount
      - TotalIssues
      - ImpactedAssets
      SortBy:
      - RiskScoreTotal
      ReportQuery:
      - |-
        // Report Purpose
        // This report highlights overdue endpoint CVEs older than 40 days, excluding out-of-scope assets, and prioritizes them using asset criticality, tag-based tiering, and exploit and exposure risk factors to focus remediation on the most critical and likely exploitable vulnerabilities.

        // Step 0  Define legacy operating systems that should increase probability
        let LegacyWindowsOSPlatforms = dynamic([
          "WindowsServer2008",
          "WindowsServer2008R2",
          "WindowsServer2012",
          "WindowsServer2012R2",
          "Windows7",
          "Windows8",
          "Windows8.1"
        ]);

        let LegacyMacOSMajorVersions = dynamic([10, 11, 12]);

        let LegacyLinuxMatchers = dynamic([
          "CentOS 7",
          "Ubuntu 18.04",
          "Debian 10",
          "RHEL 7",
          "SLES 12"
        ]);

        // Step 1  Build asset list for endpoints and attach fields used later
        // Only Endpoint assets are included
        // Customer facing and excluded flags are normalized from rawData or raw
        // Excluded assets are filtered out early
        // Existing criticality fields are kept exactly as-is
        // Tags are collected from multiple rawData locations and combined into one list
        // AssetTags is a semicolon separated string of all tags
        // AssetTierByTag is extracted from AssetTags using regex and stable sorting
        // LegacyEndOfSupport is derived from AssetProps rawData OS fields when present
        let Assets =
            ExposureGraphNodes
            | where tostring(NodeProperties.rawData.deviceCategory) == "Endpoint"
            | extend EG_IsCustomerFacing = tobool(coalesce(
                NodeProperties.rawData.isCustomerFacing,
                NodeProperties.raw.isCustomerFacing
              ))
            | extend EG_IsExcluded = tobool(coalesce(
                NodeProperties.rawData.isExcluded,
                NodeProperties.raw.isExcluded
              ))
            | where EG_IsExcluded == false
            | extend CriticalityLevel = toint(coalesce(
                tostring(NodeProperties.criticalityLevelProps[0].criticalityLevel),
                tostring(NodeProperties.rawData.criticalityLevel.criticalityLevel),
                tostring(NodeProperties.criticalityLevel.criticalityLevel)
            ))
            , CriticalityRuleBased = toint(coalesce(
                tostring(NodeProperties.criticalityLevelProps[0].ruleBasedCriticalityLevel),
                tostring(NodeProperties.rawData.criticalityLevel.ruleBasedCriticalityLevel),
                tostring(NodeProperties.criticalityLevel.ruleBasedCriticalityLevel)
            ))
            , CriticalityRuleNames = coalesce(
                strcat_array(NodeProperties.criticalityLevelProps[0].ruleNames, ", "),
                strcat_array(NodeProperties.rawData.criticalityLevel.ruleNames, ", ")
            )
            , AadDeviceId = tostring(coalesce(
                NodeProperties.rawData.aadDeviceId,
                NodeProperties.raw.aadDeviceId,
                NodeProperties.aadDeviceId
            ))
            | extend NoderawData = todynamic(NodeProperties).rawData
            | extend
                deviceManualTags  = iff(isnull(NoderawData.deviceManualTags),  dynamic([]), todynamic(NoderawData.deviceManualTags)),
                deviceDynamicTags = iff(isnull(NoderawData.deviceDynamicTags), dynamic([]), todynamic(NoderawData.deviceDynamicTags)),
                tags              = iff(isnull(NoderawData.tags.tags),         dynamic([]), todynamic(NoderawData.tags.tags))
            | extend _AllTags = array_concat(array_concat(deviceManualTags, deviceDynamicTags), tags)
            | extend AssetTags = strcat_array(_AllTags, ";")
            
            // Exclude Devices, which includes tag with '--Excluded--SI'
            | where AssetTags !has "--Excluded--SI"
            
            | extend _TierTags = extract_all(@"([^;]*--tier[0-3]--SI[^;]*)", AssetTags)
            | extend AssetTierByTag = strcat_array(array_sort_asc(coalesce(_TierTags, dynamic([]))), ";")
            | extend NodeAssetTags = _AllTags
            | extend AssetOSPlatform = tostring(coalesce(NoderawData.osPlatform, NoderawData.OSPlatform, NoderawData.platform, NoderawData.operatingSystem, NoderawData.os))
            | extend AssetOSVersion  = tostring(coalesce(NoderawData.osVersion,  NoderawData.OSVersion,  NoderawData.version,  NoderawData.operatingSystemVersion))
            | extend AssetOSDistribution = tostring(coalesce(NoderawData.osDistribution, NoderawData.OSDistribution, NoderawData.distribution))
            | extend MacMajor = toint(extract(@"^(\d+)", 1, AssetOSVersion))
            | extend IsLegacyWindows = iff(AssetOSPlatform in~ (LegacyWindowsOSPlatforms), 1, 0)
            | extend IsLegacyMacOS = iff(tolower(AssetOSPlatform) has "mac" and MacMajor in~ (LegacyMacOSMajorVersions), 1, 0)
            | extend IsLegacyLinux = iff(
                tolower(AssetOSPlatform) has "linux"
                and (AssetOSDistribution has_any (LegacyLinuxMatchers) or AssetOSVersion has_any (LegacyLinuxMatchers)),
                1, 0
              )
            | extend LegacyEndOfSupport = iff(IsLegacyWindows == 1 or IsLegacyMacOS == 1 or IsLegacyLinux == 1, 1, 0)
            | project
                AssetNodeId = NodeId,
                AssetName   = NodeName,
                AssetLabel  = NodeLabel,
                AssetProps  = NodeProperties,
                CriticalityLevel,
                CriticalityRuleBased,
                CriticalityRuleNames,
                AadDeviceId,
                EG_IsCustomerFacing,
                EG_IsExcluded,
                NodeAssetTags,
                AssetTags,
                AssetTierByTag,
                LegacyEndOfSupport;

        // Step 2  Build finding list
        // Categories is expanded to allow filtering on any category value
        // Only nodes with a category containing finding are included
        let Findings =
            ExposureGraphNodes
            | mv-expand Category = Categories
            | where tostring(Category) contains "finding"
            | project
                FindingNodeId     = NodeId,
                FindingName       = NodeName,
                FindingLabel      = NodeLabel,
                FindingCategories = Categories,
                FindingProps      = NodeProperties;

        // Step 3  Build edge list
        // Only edges with labels containing affecting are used
        // Edge properties are included when present otherwise an empty object is used
        let Edges =
            ExposureGraphEdges
            | where tostring(EdgeLabel) contains "affecting"
            | extend EdgeProps = column_ifexists("EdgeProperties", dynamic({}))
            | project SourceNodeId, TargetNodeId, EdgeLabel, EdgeProps;

        // Step 4  Relate assets and findings using edges in both directions
        // Both directions are needed because source and target can be swapped
        // The union is later de-duplicated using summarize by asset and finding identifiers
        let AF_edges_oneway =
            Edges
            | join kind=inner (Assets)   on $left.SourceNodeId == $right.AssetNodeId
            | join kind=inner (Findings) on $left.TargetNodeId == $right.FindingNodeId
            | project AssetName, AssetLabel, AadDeviceId, EG_IsCustomerFacing, EG_IsExcluded,
                      FindingName, FindingLabel, FindingCategories, FindingProps,
                      EdgeLabel, EdgeProps,
                      AssetProps, CriticalityLevel, CriticalityRuleBased, CriticalityRuleNames,
                      NodeAssetTags, AssetTags, AssetTierByTag, LegacyEndOfSupport;

        let AF_edges_otherway =
            Edges
            | join kind=inner (Assets)   on $left.TargetNodeId == $right.AssetNodeId
            | join kind=inner (Findings) on $left.SourceNodeId == $right.FindingNodeId
            | project AssetName, AssetLabel, AadDeviceId, EG_IsCustomerFacing, EG_IsExcluded,
                      FindingName, FindingLabel, FindingCategories, FindingProps,
                      EdgeLabel, EdgeProps,
                      AssetProps, CriticalityLevel, CriticalityRuleBased, CriticalityRuleNames,
                      NodeAssetTags, AssetTags, AssetTierByTag, LegacyEndOfSupport;

        let AF_edges = union AF_edges_oneway, AF_edges_otherway;

        AF_edges
            // Bucket filter support
            // DeviceKey is used for bucket filtering and distinct counting
            | extend DeviceKey = iif(isnotempty(AadDeviceId), AadDeviceId, AssetName)
            __BUCKET_FILTER__

            | summarize
                DeviceKey             = any(DeviceKey),
                EdgeLabels            = make_set(EdgeLabel),
                EdgePropsAll          = make_bag(EdgeProps),
                FindingLabel          = any(FindingLabel),
                FindingCategories     = any(FindingCategories),
                FindingProps          = any(FindingProps),
                AssetProps            = any(AssetProps),
                CriticalityLevel      = any(CriticalityLevel),
                CriticalityRuleBased  = any(CriticalityRuleBased),
                CriticalityRuleNames  = any(CriticalityRuleNames),
                AadDeviceId           = any(AadDeviceId),
                EG_IsCustomerFacing   = any(EG_IsCustomerFacing),
                EG_IsExcluded         = any(EG_IsExcluded),
                NodeAssetTags         = any(NodeAssetTags),
                AssetTags             = any(AssetTags),
                AssetTierByTag        = any(AssetTierByTag),
                LegacyEndOfSupport    = any(LegacyEndOfSupport)
              by AssetName, AssetLabel, FindingName

        // Step 5  Build a unified Properties bag for simpler lookups
        // finding holds the full finding node properties
        // raw holds rawData if present otherwise an empty object
        // edge holds combined edge properties from all related edges
            | extend Properties =
                bag_merge(
                    bag_pack("finding", FindingProps),
                    bag_pack("raw", iif(isnull(FindingProps.rawData), dynamic({}), FindingProps.rawData)),
                    bag_pack("edge", EdgePropsAll)
                )

        // Step 6  Extract scoring and filter to CVE findings
        // Impact is derived from multiple possible cvss locations
        // Severity comes from raw severity
        // Only findings where FindingLabel contains CVE are kept
            | extend Impact = todouble(coalesce(
                    Properties.raw.cvssScore,
                    Properties.finding.raw.cvssScore,
                    Properties.raw.cvss.cvssScore
                ))
            | extend SecuritySeverity = tostring(Properties.raw.severity)
            | where FindingLabel contains "CVE"

        // Step 7  Extract exploit related booleans from multiple locations
            | extend HasExploit = tobool(coalesce(
                Properties.finding.rawData.hasExploit,
                Properties.raw.hasExploit,
                Properties.finding.raw.hasExploit
            ))
            | extend IsExploitVerified = tobool(coalesce(
                Properties.finding.rawData.isExploitVerified,
                Properties.raw.isExploitVerified,
                Properties.finding.raw.isExploitVerified
            ))
            | extend IsInExploitKit = tobool(coalesce(
                Properties.finding.rawData.isInExploitKit,
                Properties.raw.isInExploitKit,
                Properties.finding.raw.isInExploitKit
            ))
            | extend IsZeroDay = tobool(coalesce(
                Properties.finding.rawData.isZeroDay,
                Properties.raw.isZeroDay,
                Properties.finding.raw.isZeroDay
            ))

        // Step 8  Compute risk factor scores at row level and build detailed strings
        // RiskFactor_Consequence is defaulted to 0 for compatibility
        // RiskFactor_Probability is a 0 to 3 score
        // Add 1 if any exploit signal is true
        // Add 1 if the asset is customer facing
        // Add 1 if the asset is legacy end-of-support
        // RiskFactor_Probability_Detailed is a semicolon separated list of factor names
        // RiskFactor_Probability_DetailedScore is a semicolon separated key value string of sub scores
            | extend RiskFactor_Consequence = 0
            | extend RF_P_ExploitSignals =
                iff(HasExploit == true or IsExploitVerified == true or IsInExploitKit == true or IsZeroDay == true, 1, 0)
            | extend RF_P_InternetExposed = iff(EG_IsCustomerFacing == true, 1, 0)
            | extend RF_P_LegacyEoS = iff(LegacyEndOfSupport == 1, 1, 0)
            | extend RiskFactor_Probability = RF_P_ExploitSignals + RF_P_InternetExposed + RF_P_LegacyEoS
            | extend RiskFactor_Probability_Detailed =
                strcat_array(
                    array_concat(
                        iff(RF_P_ExploitSignals == 1,   dynamic(["ExploitSignals"]), dynamic([])),
                        iff(RF_P_InternetExposed == 1,  dynamic(["Internet-Exposed"]), dynamic([])),
                        iff(RF_P_LegacyEoS == 1,        dynamic(["LegacyEndOfSupport"]), dynamic([]))
                    ),
                    ";"
                )
            | extend RiskFactor_Probability_DetailedScore =
                strcat(
                    "ExploitSignals=", tostring(RF_P_ExploitSignals), ";",
                    "Internet-Exposed=", tostring(RF_P_InternetExposed), ";",
                    "LegacyEndOfSupport=", tostring(RF_P_LegacyEoS)
                )

        // Step 9  Compute criticality tier with fallback to tags
        // CriticalityTierFromTag maps tier tags to a numeric tier
        // CriticalityTier prefers CriticalityLevel
        // If CriticalityLevel is missing then tier tags are used
        // If both are missing then default is 3
            | extend CriticalityTierFromTag =
                case(
                    AssetTierByTag has "--tier0--SI", 0,
                    AssetTierByTag has "--tier1--SI", 1,
                    AssetTierByTag has "--tier2--SI", 2,
                    AssetTierByTag has "--tier3--SI", 3,
                    int(null)
                )
            | extend CriticalityTier = toint(coalesce(CriticalityLevel, CriticalityTierFromTag, 3))
            | extend CriticalityTierLevel =
                case(
                    CriticalityTier == 0, "Critical - tier 0",
                    CriticalityTier == 1, "High - tier 1",
                    CriticalityTier == 2, "Medium - tier 2",
                    CriticalityTier == 3, "Low - tier 3",
                    "Unknown - unmapped"
                )

        // Step 10  Set fixed classification fields for the report output
            | extend SecurityDomain = "Endpoint"
            | extend ConfigurationName = "Update vulnerable software"
            | extend ConfigurationId = "CVE"
            | extend Category    = "Vulnerabilities"
            | extend Subcategory = "CVEs (Missing Updates)"

        // Step 11  Filter out recently updated CVEs
        // last modified is extracted from two possible locations
            | extend CVELastModified = todatetime(coalesce(Properties.finding.raw.lastModifiedDate, Properties.raw.lastModifiedDate))
            | where CVELastModified < ago(40d)

        // Step 12  Build device key used for distinct counting
        // Prefer AadDeviceId when present otherwise fall back to AssetName
            | extend DeviceKey = iif(isnotempty(AadDeviceId), AadDeviceId, AssetName)

        // Step 13  Aggregate to report level
        // Risk factors use max so the group reflects the highest score observed
        // Detailed columns use any to keep string output compatible with CSV and Excel
            | summarize
                AssetCount      = dcount(DeviceKey),
                TotalIssues     = count(),
                AvgImpact       = avg(Impact),
                MaxImpact       = max(Impact),
                ImpactedAssets  = make_set(AssetName),
                SampleCVEs      = make_set(FindingLabel),
                RiskFactor_Consequence = max(RiskFactor_Consequence),
                RiskFactor_Probability = max(RiskFactor_Probability),
                RiskFactor_Probability_Detailed = any(RiskFactor_Probability_Detailed),
                RiskFactor_Probability_DetailedScore = any(RiskFactor_Probability_DetailedScore)
              by SecurityDomain, Category, Subcategory, ConfigurationName, ConfigurationId, CriticalityTier, CriticalityTierLevel, SecuritySeverity

        // Step 14  Final shape and sorting
            | project
                SecurityDomain,
                Category,
                Subcategory,
                ConfigurationName,
                ConfigurationId,
                CriticalityTier,
                CriticalityTierLevel,
                SecuritySeverity,
                RiskFactor_Consequence,
                RiskFactor_Probability,
                RiskFactor_Probability_Detailed,
                RiskFactor_Probability_DetailedScore,
                AssetCount,
                TotalIssues,
                AvgImpact = round(AvgImpact, 1),
                MaxImpact = toint(ceiling(MaxImpact)),
                ImpactedAssets,
                SampleCVEs
            | order by CriticalityTier asc, MaxImpact desc, AvgImpact desc, AssetCount desc, TotalIssues desc

```



### Example of Report Templates

```
ReportTemplates:
    - ReportName: RiskAnalysis_Detailed_Bucket
      ReportPurpose: Overview
      ReportsIncluded:
      - Name: Device_Recommendations_Detailed_BucketFilter
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Device_Missing_CVEs_Detailed_BucketFilter
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Azure_Recommendations_Detailed_BucketFilter
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Attack_Paths_Detailed_BucketFilter_Identity_Group_Membership_to_Privileged_Resources
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Attack_Paths_Detailed_BucketFilter_Data_Sensitivity_to_Exposed_Credentials
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Attack_Paths_Detailed_BucketFilter_Credential_Based_Lateral_Movement
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Attack_Paths_Detailed_BucketFilter_Github_to_Azure_Resources
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Attack_Paths_Detailed_BucketFilter_Public_IP_to_VM_with_CVE_Exploitation
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__


    - ReportName: RiskAnalysis_Summary_Bucket
      ReportPurpose: Overview
      ReportsIncluded:
      - Name: Device_Recommendations_Summary_BucketFilter
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Device_Missing_CVEs_Summary_BucketFilter
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Azure_Recommendations_Summary_BucketFilter
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Attack_Paths_Summary_BucketFilter_Identity_Group_Membership_to_Privileged_Resources
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Attack_Paths_Summary_BucketFilter_Data_Sensitivity_to_Exposed_Credentials
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Attack_Paths_Summary_BucketFilter_Github_to_Azure_Resources
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
      - Name: Attack_Paths_Summary_BucketFilter_Public_IP_to_VM_with_CVE_Exploitation
        UseQueryBucketing: true
        DefaultBucketCount: 2
        BucketPlaceholderToken: __BUCKET_FILTER__
```
