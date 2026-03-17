# SecurityInsight
Rethink **Secure Score** into a **new risk-based security risk score**, based on **consequence, probability** and **risk factors**. Solution includes **critical asset tagging**, **ready-to-use reports** (based on Defender Exposure Graph and Azure Resource Graphs Kusto queries), **automation-scripts,** **risk index** and more

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
  - [Endpoint / Device Asset Criticality Classification](#endpoint--device-asset-criticality-classification)
  - [Identity Asset Criticality Classification](#identity-asset-criticality-classification)
  - [Cloud (Azure) Asset Criticality Classification](#cloud-azure-asset-criticality-classification)
  - [SaaS (Apps) Asset Criticality Classification](#saas-apps-asset-criticality-classification)
  - [Data Asset Criticality Classification](#data-asset-criticality-classification)

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

# Executive Summary
My customer loves the solution as it allows them to take better decisions on which recommendations to fix – with respect of the criticality level/priority of the asset – combined with lots of contextual risk factors
To simplify it: you take the first line in the Excel spreadsheet, as it has the highest “risk score”. The higher risk score, the more important is the recommendation.


### 🧩 What it is

**SecurityInsight is a risk-based prioritization solution for Microsoft security findings.**

It rethinks traditional tools like Secure Score by introducing a **custom risk scoring model** based on:

- consequence (impact)
- probability (likelihood)
- contextual risk factors

Its core purpose is simple:

> **Help security teams decide what to fix first — based on real risk, not just severity.**



### 🚨 Problem it solves

**SecurityInsight addresses the lack of meaningful prioritization in modern security tooling.**

In typical environments:

- Thousands of vulnerabilities and recommendations exist
- Many are labeled “high” or “critical”
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

- Internet exposure
- Known exploits
- Legacy systems



### 🏷️ Critical asset tagging

**SecurityInsight classifies assets by importance**, for example:

- **Tier-0 (Critical):** Global Admins, Domain Admins, break-glass accounts
- **Tier-1 / Tier-2 / Tier-3:** decreasing importance

👉 The same vulnerability becomes higher priority when it affects critical assets.



### 🕸️ Graph-based analysis

**SecurityInsight uses graph-based security data (Exposure Graph)** to:

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

- attack chains and relationships are not identified.


Although these tools are effective at identifying problems, they rarely answer the most important question: **Which issues should be addressed first?**

In practice, remediation work is often prioritized according to:

- technical severity
- number of affected systems
- ease of remediation

 This often leads organizations to spend resources resolving issues with limited real risk while more critical exposures remain unaddressed.

------



# A Risk-Based Prioritization Model

The **Security Insight** framework introduces a **risk-based prioritization model** that evaluates security findings based on both consequence and probability.

```
Risk Score = Consequence Score × Probability Score
```

**Consequence Score** represents the potential impact if a vulnerability is exploited.

**Probability Score** represents the likelihood that the vulnerability will actually be exploited.

The model can also be influenced by **contextual risk factors** such as:

- internet exposure
- known exploits
- legacy systems
- +more can be added along the way !

These factors will each increase the probability score with +1 - and therefore indirectly increasing the overall risk score.

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

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/AttackPath-Sample-EntraCookie-1.png)

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/AttackPath-Sample-EntraCookie-2.png)

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/AttackPath-Sample-EntraCookie-3.png)

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/AttackPath-Sample-EntraCookie-4.png)

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/AttackPath-Sample-EntraCookie-5.png)

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/AttackPath-Sample-EntraCookie-6.png)

------



## Why Graph Architecture Matters

A **graph model** allows security platforms to:

- **Map relationships between assets**
- **Identify possible attack paths**
- **Detect lateral movement opportunities**
- **Prioritize exposures that could lead to high-impact compromise**

Instead of asking *“What vulnerabilities exist?”*, a graph-based system asks:

> *“Which vulnerabilities could actually lead to a critical system being compromised?”*

This relationship-based view is what makes exposure graphs powerful for **modern threat detection and attack path analysis**.



The **Security Insight model** therefore uses **Exposure Graph** analysis to identify relationships between assets, identities, vulnerabilities and configuration issues. Data is coming from:

- ExposureGraphNodes

- ExposureGraphEdges
- Defender Vulnerability Management findings
- configuration assessments

 These datasets allow analysis of relationships between systems and security findings.

------



# Risk Score Model

**Risk Score** is calculated using two dimensions:

**Consequence Score** – the potential impact if exploitation occurs.

**Probability Score** – the likelihood of exploitation based on asset tier and exposure context.



**Probability Score** may be adjusted using **contextual risk indicators (risk factors)**, that increase the likelihood of exploitation. such as:

- **Active exploitation:** If the vulnerability is currently being exploited in the wild, the likelihood of compromise is significantly higher.
- **Public exploit code:** Proof-of-concept exploit code is publicly available, lowering the barrier for attackers to exploit the vulnerability.
- **Internet exposure:** Systems accessible from the internet increase the likelihood of exploitation.
- **Legacy systems:** Older or unsupported systems may lack security updates and increase vulnerability risk.

 Each of these influence the score by increasing the probability score with +1 due to the risk factor



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



![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/Riskscore-Sample-Zoom.png)

Line #1 with score of 20 is the most critical thing to fix, based on the calculation. Then the next lines with risk score 15, 12, 10, etc.



Calculation sample (line #1):

```
Severity: 4
Probability:5 (4 + 1 due to risk factor 'internet exposed'). 4 is coming from risk index
Risk Score: 20 (4 x 5)
```

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/Riskscore-Sample.png)



### Severity Prioritization | Risk Score Definitions

[Download as Excel file](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/Risk%20Score%20Definitions.xlsx)

| Defender Severity Score | Severity Category | Severity description                                         |
| ----------------------- | ----------------- | ------------------------------------------------------------ |
| 10                      | Very High Risk    | If this configuration is not applied, attackers gain a major foothold or common attack vector remains wide open. |
| 9                       | High Risk         | Strongly recommended to fix ASAP; commonly exploited by real-world malware and ransomware. |
| 8                       | Medium-High Risk  | Important baseline security hardening; reduces attack surface and lateral movement. |
| 5-7                     | Medium Risk       | Security best practice; helps reduce exposure but less frequently exploited. |
| 1-4                     | Low Risk          | Hardening / hygiene controls; helps, but attackers less likely to target. |



### Criticality Prioritization | Risk Score Definitions

**Disclaimer:**
The asset criticality classifications presented here are based on my professional judgment and experience. Actual classifications may vary depending on each organization’s specific environment, risk tolerance, regulatory requirements, architecture, and operational priorities.

[Download as Excel file](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/Risk%20Score%20Definitions.xlsx)

| Criticality Level Name<br />(Tier) | Criticality Description                                      | Compromise Impact                                            | Defender terms (portal) | Defender terms (API)<br />criticalityLevel |
| ---------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ----------------------- | ------------------------------------------ |
| Critical<br />(Tier-0)             | Identity or infrastructure trust anchors that control authentication, authorization, encryption, or global security boundaries.<br/><br/>Assets that, if compromised, give an attacker full control of the organization, identity fabric, or security boundary. These are the crown jewels. | Compromise Impact<br/>Full organizational takeover, persistent compromise likely. | Very High - tier 0      | 0                                          |
| High<br />(Tier-1)                 | Systems that configure, orchestrate, or grant access to Tier 2/3 assets.<br/><br/>Systems that manage or enforce configuration on lower-tier assets. If compromised, they enable privilege escalation or widespread lateral movement.<br/><br/>Business-critical platforms or workloads supporting core operations.<br/><br/>Standard production systems that host sensitive but non-root-of-trust workloads. Compromise impacts specific business functions but not identity fabric control. | Rapid privilege escalation or environment-wide misconfiguration.<br/><br/>Business disruption, focused operational risk. | High - tier 1           | 1                                          |
| Medium<br />(Tier-2)               | Tier 2 (User & Developer Endpoints):<br/>Real users authenticate and access business resources, but these systems do not control identity or the security control plane.<br/>Compromise typically impacts a user, team, or non-production environment (data loss, token theft, lateral movement within Tier 2). |                                                              | Medium - tier 2         | 2                                          |
| Low<br />(Tier-3)                  | Tier 3 (Low-Trust / Shared / Disposable):<br/>Shared, anonymous, or intentionally isolated systems (kiosk-style or disposable labs).<br/>Assume high compromise likelihood and design for minimal blast radius (tight isolation, frequent reset/wipe, no privileged access). | Local impact; lateral movement required to escalate.         | Low - tier 3            | 3                                          |



### Endpoint / Device Asset Criticality Classification

**Disclaimer:**
The asset criticality classifications presented here are based on my professional judgment and experience. Actual classifications may vary depending on each organization’s specific environment, risk tolerance, regulatory requirements, architecture, and operational priorities.

[Download as Excel file](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/Risk%20Score%20Definitions.xlsx)

| Criticality Level      | Typical Assets                                               |
| ---------------------- | ------------------------------------------------------------ |
| Critical<br />(tier-0) | Server Roles:<br/>* Active Directory Domain Services (AD DS)<br/>* Active Directory Certificate Services (AD CS)<br/>* Active Directory Federation Services (AD FS) trust root configuration<br/>* DNS integrated with AD for domain trust management<br/>Azure AD Connect Sync engine<br/>* On-prem Authentication Broker Servers (e.g., PTA agents, federation bridges)<br/>* Azure AD DS Domain Services instances (if used)<br/>* Entra ID Connect Servers (Hybrid Identity Sync)<br/><br/>Management:<br/>* Privileged Access Workstations (PAWs)<br/>* Security Management Servers (MDE, MDEr, EDR collectors)<br/><br/>Infrastructure:<br/>* Hardware Security Modules (HSM appliances or Azure Key Vault HSM-backed)<br/><br/>HyperVisor:<br/>* Hypervisor Hosts (VMware ESXi, Hyper-V clusters hosting Tier-0 assets) |
| High<br />(Tier-1)     | Server Roles:<br/>* Endpoint Management Admin Servers<br/>* RADIUS / NPS Authentication servers<br/>* Backup Management Systems<br/>* Patch Management Servers<br/>* Enterprise Firewall/Proxy Management Consoles<br/>* Federated Identity Components (e.g., SSO Gateways, OAuth Brokers)<br/>* Print Spooler servers with elevated AD access risk<br/><br/>* Business application servers (ERP, CRM, HR, Finance, etc.)<br/>* Tiered database servers (data-important but not identity-root)<br/>* File/print servers<br/>* Production line-of-business application VMs<br/>* Middleware or API integration servers<br/>* Jump hosts for application operations (not identity or security ops)<br/>* Web servers hosting business systems (IIS / NGINX / Apache)<br/>* Application middleware servers (Tomcat, WebLogic, SAP dispatcher)<br/>* Standard SQL / NoSQL databases containing operational business data |
| Medium<br />(Tier-2)   | * Employee laptops & desktops<br/>* Employee mobile phones<br/>* Non-admin VDI clients<br/>* Developer test machines<br/>* Training, demo environments<br/>* QA / staging servers (non-prod)<br/>* Non-production dev/test environments<br/>* Internal wiki or documentation servers<br/>* Local print/file servers without privilege exposure |
| Low<br />(Tier-3)      | * Kiosks and shared access terminals<br/>* Shared/kiosk mobile devices (exception only: no corporate mailbox, no MFA approval, reset/wipe frequently) |



### Identity Asset Criticality Classification

**Disclaimer:**
The asset criticality classifications presented here are based on my professional judgment and experience. Actual classifications may vary depending on each organization’s specific environment, risk tolerance, regulatory requirements, architecture, and operational priorities.

[Download as Excel file](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/Risk%20Score%20Definitions.xlsx)

| Criticality Level      | Typical Assets                                               |
| ---------------------- | ------------------------------------------------------------ |
| Critical<br />(tier-0) | Cloud - Entra ID Roles:<br/>* Global Administrator accounts<br/>* Privileged Authentication Administrator<br/>* Privileged Role Administrator<br/>* Directory Synchronization Service Accounts<br/>* Break-glass Emergency Access Accounts<br/>* Directory Writers<br/><br/>Cloud - Entra ID Services:<br/>* Conditional Access and Identity Governance core policies<br/><br/>AD:<br/>* Domain Admins<br/>* Enterprise Admins<br/>* Schema Admins<br/>* Administrators (Built-in)<br/>* Key Admins / Crypto Admins<br/>* Cert Publishers<br/>* Group Policy Creator Owners<br/>* Incoming Forest Trust Builders<br/>* Protected Users Group<br/>* Privileged Kerberos delegation accounts<br/><br/>Azure:<br/>* Privileged Credential Vault Root Access |
| High<br />(Tier-1)     | Entra ID:<br/>* Security Administrator accounts<br/>* Application Administrator accounts<br/>* Conditional Access Administrators<br/>* Exchange / SharePoint / Teams Admins (Privileged variants)<br/><br/>AD:<br/>* Server Operators<br/>* Backup Operators<br/>* Print Operators (privilege escalation risk in AD)<br/>* Network Configuration Operators<br/><br/>Accounts:<br/>* Helpdesk Administrator accounts with delegated reset access<br/>* Tier-1 admin accounts (Scoped to systems supporting Tier-0 assets indirectly) |
| Medium<br />(Tier-2)   | Entra ID / Identity (Tier 2):<br/>* Standard user accounts (employees)<br/>* Developer user accounts (non-privileged)<br/>* Guest / B2B external collaborators (low-privilege access)<br/>* Non-privileged test accounts<br/>* Workload identities used only for Tier-2 / non-production workloads (no privileged role assignments) |
| Low<br />(Tier-3)      | Identity (Tier 3):<br/>* Shared kiosk identities (where unavoidable)<br/>* Temporary / disposable lab identities with no access to corporate data<br/>* Local-only accounts on kiosk or shared devices |



### Cloud (Azure) Asset Criticality Classification

**Disclaimer:**
The asset criticality classifications presented here are based on my professional judgment and experience. Actual classifications may vary depending on each organization’s specific environment, risk tolerance, regulatory requirements, architecture, and operational priorities.

[Download as Excel file](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/Risk%20Score%20Definitions.xlsx)

| Criticality Level      | Typical Assets                                               |
| ---------------------- | ------------------------------------------------------------ |
| Critical<br />(tier-0) | Azure (services):<br/>* Azure Key Vaults storing tenant root keys or certificate authorities<br/>* Immutable and Locked Azure Storage holding identity bootstrap data<br/><br/>Azure (delegations):<br/>* Azure Management Groups with root tenant-level access<br/>* Azure Subscription Owner roles over security-critical subscriptions |
| High<br />(Tier-1)     | Azure:<br/>* Azure Virtual Machines with privileged tokens or identities assigned<br/>* Highly active Azure Key Vaults with large number of operations<br/>* Azure Automation / Runbook accounts with role assignments<br/>* Azure Arc / Hybrid management orchestrators<br/>* Azure Network and Security Policy control plane resources |
| Medium<br />(Tier-2)   | Azure (Tier 2):<br/>* Dev/Test subscriptions and resource groups<br/>* Non-production workloads (dev, test, QA, staging) without production data<br/>* End-user virtual desktop services (AVD / Windows 365) for non-admin users<br/>* Personal / sandbox resources with no privileged role assignments |
| Low<br />(Tier-3)      | Azure (Tier 3):<br/>* Sandbox subscriptions designed for experimentation<br/>* Proof-of-concept / pilot workloads with no sensitive data<br/>* Lab resource groups intended to be wiped/reset |



### SaaS (Apps) Asset Criticality Classification

**Disclaimer:**
The asset criticality classifications presented here are based on my professional judgment and experience. Actual classifications may vary depending on each organization’s specific environment, risk tolerance, regulatory requirements, architecture, and operational priorities.

[Download as Excel file](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/Risk%20Score%20Definitions.xlsx)

| Criticality Level      | Typical Assets                                               |
| ---------------------- | ------------------------------------------------------------ |
| Critical<br />(tier-0) | Entra ID (app-permissions):<br/>* Service Principals with Directory.ReadWrite.All or Organization-wide write permissions<br/><br/>Identity integration:<br/>* Identity provider / SSO configuration applications (Enta ID, Okta, PingFed bridges)<br/><br/>Management Portals:<br/>* Core tenant admin portals (Entra Admin Center, Azure Portal with Owner/GA access) |
| High<br />(Tier-1)     | Cloud:<br/>* Intune<br/>* Backup<br/><br/>Entra ID integrations:<br/>* SPNs with elevated delegated OAuth permissions (user impersonation capabilities)<br/>* Line-of-business SaaS systems with admin-level access rights<br/>* Service accounts with Exchange/SharePoint/Teams admin rights<br/>* M365 platform-wide configuration access applications<br/>* Directory-synced SaaS environments with strong platform integration |
| Medium<br />(Tier-2)   | * Business SaaS platforms with departmental administrator rights<br/>* Project management platforms<br/>* Document collaboration SaaS applications (non-sensitive)<br/>* CRM / HR / Finance SaaS platforms with departmental administrators<br/>* SharePoint Online site admins (for business units, not tenant-level) |
| Low<br />(Tier-3)      | * Low-sensitivity SaaS (department task apps, wiki tools, non-auth-critical)<br/>* Trial / evaluation SaaS instances<br/>* Dev/test application tenants<br/>* Collaboration productivity apps (non-admin roles)<br/>* Low-sensitivity workflow or forms applications |



### Data Asset Criticality Classification

**Disclaimer:**
The asset criticality classifications presented here are based on my professional judgment and experience. Actual classifications may vary depending on each organization’s specific environment, risk tolerance, regulatory requirements, architecture, and operational priorities.

[Download as Excel file](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/Risk%20Score%20Definitions.xlsx)

| Criticality Level      | Typical Assets                                               |
| ---------------------- | ------------------------------------------------------------ |
| Critical<br />(tier-0) | * Root encryption keys (HSM / Key Vault root keys)<br/>* Token signing certificates (AD FS, Azure AD B2C, SAML Identity Providers)<br/>* Identity bootstrap credentials / trust chain material<br/>* Domain / Directory backup archives and snapshots<br/>* Privileged credential vault master keys |
| High<br />(Tier-1)     | * Line-of-business application configuration databases<br/>* Enterprise configuration backups<br/>* PKI intermediate CAs and signing authorities<br/>* Operational secrets stores for applications and APIs |
| Medium<br />(Tier-2)   | * Business process data<br/>* Departmental shared files<br/>* Standard application configuration data<br/>* Non-identity-securing configuration data |
| Low<br />(Tier-3)      | * Non-sensitive content repositories<br/>* Training data<br/>* Internal public documentation<br/>* Documentation and knowledge base files<br/>* Non-sensitive departmental shared files |



### Risk Index - How we prioritize scoring (customizable)?

**Disclaimer:**
The risk scoring and prioritization model presented in this table is based on my personal assessment and general security best practices. The scoring methodology, severity levels, and criticality tiers are intended as a customizable reference framework. Actual risk prioritization may vary between organizations depending on their infrastructure, business impact, regulatory requirements, threat landscape, and risk tolerance.

[Download as CSV-file](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/SecurityInsight_RiskIndex.csv)

| Security<br />Domain | Category           | Sub<br />Category | ConfigurationId | Security<br />Severity | Risk<br />Consequence<br />Score_<br />Security<br />Severity | Criticality<br />TierLevel | Risk<br />Probablity<br />Score_<br />Criticiality<br />TierLevel | Comments                                                     |
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
|                      |                    |                   |                 | Medium                 | 1                                                            | Low - tier 3               | 1                                                            |                                                              |
|                      |                    |                   |                 | Medium                 | 1                                                            | Low - tier 3               | 1                                                            |                                                              |
|                      |                    |                   |                 | Medium                 | 1                                                            | Low - tier 3               | 1                                                            |                                                              |
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

**Summary reports** include number of findings per tier, overall risk levels, configuration status

**Detailed reports** include affected assets, vulnerability identifiers and remediation guidance.



| File Name                                                    | Purpose                                         |
| ------------------------------------------------------------ | ----------------------------------------------- |
| [Sample - RiskAnalysis_Summary_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/Sample%20-%20RiskAnalysis_Summary_Bucket.xlsx) | Sample summary output Excel file                |
| [Sample - RiskAnalysis_Detailed_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/Sample%20-%20RiskAnalysis_Detailed_Bucket.xlsx) | Sample detailed output Excel file               |
| [Sample mail - Summary report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20mail%20-%20Summary%20report%20with%20AI%20summary.pdf) | Sample mail for Summary report with AI summary  |
| [Sample mail - Detailed report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20mail%20-%20Detailed%20report%20with%20AI%20summary.pdf) | Sample mail for Detailed report with AI summary |

------



# Governance and Compliance

The model supports several important security frameworks.



### NIS2 Directive

NIS2 requires organizations to implement:

- risk-based cybersecurity management
- protection of critical infrastructure
- preventive security measures.

The described model supports these requirements by prioritizing protection of the organization’s most critical systems.



### CIS Critical Security Controls

The model aligns with several CIS controls, including:

- CIS Control 1 – Asset Inventory
- CIS Control 4 – Secure Configuration
- CIS Control 7 – Vulnerability Management
- CIS Control 12 – Network Infrastructure Management.

 

------



# Operational Benefits

The risk-based model provides several advantages:

- **Clear security priorities** - Security teams can focus on the most critical risks.
- **Reduced operational noise** - Low-risk issues do not dominate remediation efforts.
- **Faster risk reduction** - The most dangerous vulnerabilities are addressed first.
- **Improved executive communication** - Risk scores translate technical findings into **business risk**.

------



# Future Opportunities

Potential future developments include:

- automated attack path analysis - more queries

- integration with ticketing and risk management platforms.

------




# Transparency and Flexibility

A key strength of the Security Insight model is its **transparent and flexible architecture**.

Unlike many traditional security solutions, where prioritization logic is embedded in proprietary algorithms, this model is designed to be **fully open and configurable**.

The architecture is based on widely available technologies, allowing organizations to understand and adjust the prioritization model according to their own needs.

Core components include:

- **Kusto Queries (KQL)** for security data analysis
- **PowerShell** for automation and report generation
- **CSV-based index files** defining risk scoring
- **Asset tagging** for classification of critical systems.

This approach ensures that the model is **100% transparent and open**.

 

------



# Collaboration with Microsoft

The development of the Security Insight model is conducted in close dialogue with Microsoft.

The risk-based approach to prioritizing security recommendations—based on asset criticality and exposure analysis—has attracted significant interest within Microsoft’s security organization.

**Morten Knudsen works closely with Microsoft, including Raviv Tamir, Corporate Vice President for Microsoft Defender, and his team.**

The goal of this collaboration is to explore how the principles behind the Security Insight model can influence the future development of the **Microsoft Defender platform**.

------



# Files Overview

### Asset Tagging

| File Name                                                    | Purpose                                                      | Continues Updates via UpdateSecurityInsight-script |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| [RunCriticalAssetTagging.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/RunCriticalAssetTagging.ps1) | Engine Launcher for Asset Tagging<br />Includes parameters for starting asset tagging engine | No (custom file)                                   |
| [CriticalAssetTagging.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/CriticalAssetTagging.ps1) | Main Engine for Asset Tagging<br />Uses YAML-files as data repo | Yes <br />                                         |
| [SecurityInsight_CriticalAssetTagging_Custom.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_CriticalAssetTagging_Custom.yaml) | Data file (custom tags)<br />Kusto queries against graph-engines | No <br />(individual asset tags)                   |
| [SecurityInsight_CriticalAssetTagging_Locked.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_CriticalAssetTagging_Locked.yaml) | Data file (recommended tags)<br />Kusto queries against graph-engines | Yes                                                |



### Asset Tagging Maintenance - Clean-up/Remove orphaned tags

| File Name                                                    | Purpose                                                      | Continues Updates via UpdateSecurityInsight-script |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| [RunCriticalAssetTaggingMaintenance.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/RunCriticalAssetTaggingMaintenance.ps1) | Maintenance Launcher<br />Includes parameters for starting maintenance engine | No (custom file)                                   |
| [CriticalAssetTaggingMaintenance.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/CriticalAssetTaggingMaintenance.ps1) | Main Engine for Asset Tag Maintenance<br /><br />Note: <br />Samples are provided that can be run after modifcation to your needs, like which tags to remove | Yes                                                |



### Risk Analysis

| File Name                                                    | Purpose                                                      | Continues Updates via UpdateSecurityInsight-script |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| [RunSecurityInsight.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/RunSecurityInsight.ps1) | Engine Launcher<br />Includes parameters for starting risk analysis engine | No (custom file)                                   |
| [SecurityInsight_RiskAnalysis.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskAnalysis.ps1) | Main Engine <br />Engine file for Risk Analysis<br />Uses YAML-files as data repo<br />Uses RiskIndex-file to prioritize score | Yes <br />                                         |
| [SecurityInsight_RiskIndex.csv](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskIndex.csv) | Risk Index data file                                         | No (*)<br />(custom priority file)                 |
| [SecurityInsight_RiskAnalysis_Queries_Custom.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskAnalysis_Queries_Custom.yaml) | Report data file (custom tags)<br />Kusto queries against graph-engine | No <br />(custom queries)                          |
| [SecurityInsight_RiskAnalysis_Queries_Locked.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskAnalysis_Queries_Locked.yaml) | Report data file (recommended tags)<br />Kusto queries against graph-engine | Yes                                                |

(*) If you don't make custom changes in RiskIndex file, you can add the file into UpdateSecurityInsight.ps1 script to subscribe to my recommendations in priority.



### Support file

| File Name                                                    | Purpose                                                      | Comment                        |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------ |
| [UpdateSecurityInsight.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/UpdateSecurityInsight.ps1) | Update Engine<br />Backup local files + Update files from [Github repo](https://github.com/KnudsenMorten/SecurityInsight) | Can be modified to your needs  |
| [Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1) | Deploy OpenAI PAYG instance (optional)<br />Used for AI summary based on context from risk analysis | Must be modified to your needs |



### Sample Output files

| File Name                                                    | Purpose                                         |
| ------------------------------------------------------------ | ----------------------------------------------- |
| [Sample mail - Detailed report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20mail%20-%20Detailed%20report%20with%20AI%20summary.pdf) | Sample mail for Detailed report with AI summary |
| [Sample - RiskAnalysis_Detailed_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20-%20RiskAnalysis_Detailed_Bucket.xlsx) | Sample detailed output Excel file               |
| [Sample mail - Summary report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20mail%20-%20Summary%20report%20with%20AI%20summary.pdf) | Sample mail for Summary report with AI summary  |
| [Sample - RiskAnalysis_Summary_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20-%20RiskAnalysis_Summary_Bucket.xlsx) | Sample summary output Excel file                |

------

  


# High-level Overview of Implementation

Detailed actions for each steps are outlined in the sections below the High-level Overview of Implementation table.

| Step                                                         | Detailed actions                                             |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| Step 1: **Prepare** SecurityInsight **files** on automation-server | 1.1. Download all files from Github and create folder on automation/batch-server<br /><br />1.2. Installation of necessary Powershell modules on server |
| Step 2: **Onboarding** of Entra App registration - to be used with SecurityInsight | 2.1. Create Entra App registration (SPN) with Secret<br /><br />2.2. Delegate permissions in API permissions<br /><br />2.3. Delegate permissions in Azure |
| Step 3: Setting **Asset Tier Level** using tagging <br />(using script from SecurityInsight) | 3.1. Adjust the authentication details in launcher file<br /><br />3.2. Validate WhatIfMode<br /><br />3.3. Run Critical Asset launcher to tag recommended tags in PROD mode<br /><br />3.4. [PROD]  Setup Recurring job to run every x hours<br /><br />3.5. [TEST]  Adjust custom yaml-file to tag resources in Test-mode<br /><br />3.6. [TEST]  Run Critical Asset launcher to tag recommended tags in TEST mode<br /><br />3.7. [PROD]  Adjust queries to Prod-mode once happy |
| Step 4: Setting **Asset Criticality Level** Classification (in Defender) | Step 4.1 - How to setup Criticality Tier Level against Azure resources?<br /><br />Step 4.2 - How to setup Criticality Tier Level against Defender device resources?<br /><br />What am I missing in Critical Asset Management - Dialog with Microsoft in progress ? |
| Step 5: Run **Risk Analysis**                                | Step 5.1. Adjust the **authentication + smtp details** in launcher file, RunSecurityInsight.ps1<br/><br />Step 5.2A.  Run Risk Analysis launcher in SUMMARY mode (cmdline)<br/><br />Step 5.2B.  Run Risk Analysis launcher in DETAILED mode (GUI/ISE mode, alternative)<br/><br />Step 5.2C.  Run Risk Analysis launcher in DETAILED mode (cmdline)<br/><br />Step 5.2D.  Run Risk Analysis launcher in DETAILED mode (GUI/ISE mode, alternative)<br/><br />Step 5.2E.  Run Risk Analysis launcher for Custom Report Template (cmdline)<br/><br />Step 5.3A. Deploy OpenAI instance to enable AI Support, Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1<br/><br />Step 5.3B. Run Risk Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1 to deploy AI instance<br/><br />Step 5.3C. Adjust the Risk Analysis launcher file to enable AI summary support (RunSecurityInsight.ps1) |

------



## Step 1: Prepare SecurityInsight files on automation-server

### 1.1. [Download all files from Github site](https://github.com/KnudsenMorten/SecurityInsight/archive/refs/heads/main.zip) and create folder on automation/batch-server

```
<drive>\SCRIPS\SecurityInsight
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

By default, Authentication is done with Secret. 

Feel free to adjust login in the launcher files to store data in Keyvault, use certificate, etc. <br />

### 2.2. Delegate API permissions to Entra App SPN

Add the below mentioned API permissions -  found under 'APIs my organization uses' <br />Remember: **Grant Admin Control**<br />

```
Microsoft Threat Protection -> AdvancedHunting.Read.All
Microsoft Graph -> ThreatHunting.Read.All
WindowsDefenderATP -> Machine.ReadWrite.All
```

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/EntraApp-API-Permissions.png)



### 2.3. Delegate 'Tag Contributor' permissions in Azure to Entra App SPN on Tenant Root-level to ensure the possibility to tag all Azure resources<br />

```
Tag Contributor (least privilege)
```

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/EntraApp-Azure-Permissions.png)

------



## Step 3: Setting Asset Tier Level using tagging 

Assets** are automatically classified using tagging rules based on system roles. Examples include:

- Domain Controllers
- Entra synchronization services
- employee devices
- IoT devices

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/MDE-Asset-Tag-Recommended-Samples.png)



**Asset tagging** is done using asset taging engine that queries resources against **Defender Graph** or **Azure Resource Graph** using **Kusto KQL**. 

Each query also includes the Asset Tag to set. 

Query shows only deltas (missing assets). 

Asset Tagging runs with defined frequency like every 4 hours.



### Structure of query in YAML-file

| Property                                                     | Purpose                                                      |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| AssetTagName                                                 | Description                                                  |
| Mode                                                         | Implementation scope <br />(can be defined in launcher or commandline)<br /><br />Supported values:<br />Prod<br />Test |
| QueryEngine                                                  | Select query engine<br /><br />Supported values:<br />DefenderGraph = ExposureGraph<br />AzureResourceGraph = Azure Resource Graph |
| Query structure<br /><br />Step 1: Scoping - what to find ?<br />Step 2: Get existing Tags "as-is"<br />Step 3: Define Value for tag to set "to-be"<br />Step 4: Write resources<br />Step 5: Filter resources to show only resources in scope with missing tag (delta) | Query the Graph<br /><br />AssetTagType supported values: <br />AssetTier--SI = shows asset is in-scope with tier-info<br />Asset--Excluded--SI = shows asset must be excluded<br /><br />AssetTag = any value that makes the asset unique<br /><br />AssetTierLevel = 0,1,2,3 |



### Asset Tagging files

| File Name                                                    | Purpose                                                      | Continues Updates via UpdateSecurityInsight-script |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| [RunCriticalAssetTagging.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/RunCriticalAssetTagging.ps1) | Engine Launcher for Asset Tagging<br />Includes parameters for starting asset tagging engine | No (custom file)                                   |
| [CriticalAssetTagging.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/CriticalAssetTagging.ps1) | Main Engine for Asset Tagging<br />Uses YAML-files as data repo | Yes <br />                                         |
| [SecurityInsight_CriticalAssetTagging_Custom.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_CriticalAssetTagging_Custom.yaml) | Data file (custom tags)<br />Kusto queries against graph-engines | No <br />(custom asset tags)                       |
| [SecurityInsight_CriticalAssetTagging_Locked.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_CriticalAssetTagging_Locked.yaml) | Data file (recommended tags)<br />Kusto queries against graph-engines | Yes                                                |



### Step 3.1. Adjust the authentication details in launcher file, RunCriticalAssetTagging.ps1 (SpnTenantId, SpnClientId, SpnClientSecret)

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
RunCriticalAssetTagging_Automation_Framework.ps1 -SCOPE PROD

Sample:
<Drive>:\SCRIPTS\SecurityInsights\RunCriticalAssetTagging_Automation_Framework.ps1 -SCOPE PROD
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



> **IMPORTANT:**
> Tagging Engine will take any queries in PROD-mode, aggregating queries from both data files:
> SecurityInsight_CriticalAssetTagging_Custom.yaml
>
> SecurityInsight_CriticalAssetTagging_Locked.yaml



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



### Step 3.4. [PROD]  Setup Recurring job to run every x hours using task scheduler or 3rd party software like VisualCron. This job should only run the queries, that have been tested and validated and moved into PROD status

```
RunCriticalAssetTagging_Automation_Framework.ps1 -SCOPE PROD

Sample:
<Drive>:\SCRIPTS\SecurityInsights\RunCriticalAssetTagging_Automation_Framework.ps1 -SCOPE PROD
```



### Step 3.5. [TEST]  Adjust custom yaml-file to tag resources in Test-mode

You can choose to modify sample TEST-queries and fine-tune the queries to match your environment.

Fine-tuning often requires adjustment according to **naming convention (Defender)**, **management-group naming (Azure)** or **IP subnets (backbone/network)**

| AssetTagName                                | What needs to be changed in Query?                           |
| ------------------------------------------- | ------------------------------------------------------------ |
| AzHubPlatformManagementSub--tier0--SI       | Name of management group ?<br /><br /> where properties.managementGroupAncestorsChain has "mg-platform-management" |
| AzHubPlatformManagementResources--tier0--SI | Name of management group ?<br /><br /> where properties.managementGroupAncestorsChain has "mg-platform-management" |
| AzHubPlatformSecuritySub--tier0--SI         | Name of management group ?<br /><br /> where properties.managementGroupAncestorsChain has "mg-platform-security" |
| AzHubPlatformSecurityResources--tier0--SI   | Name of management group ?<br /><br /> where properties.managementGroupAncestorsChain has "mg-platform-security" |
| AzLZDatacenterSub--tier0--SI                | Name of management group ?<b<br /><br /> where (properties.managementGroupAncestorsChain has "platform-prod") or (properties.managementGroupAncestorsChain has "platform-test") |
| AutomationServer--tier0--SI                 | Name of server?<br /><br /> where NodeName has "MGMT1"       |
| ServerBusinessServices--tier1--SI           | Fine-tune query to proper filter of which servers should be tier-0, tier-1, tier-2<br /><br />If you do nothing, as servers will be tagged as 'ServerBusinessServices--tier1--SI' - except if they already have a tier-0 tag (like DCs, Entra Connect, etc) |
| PAWDevices--tier0--SI                       | Adjust naming convention for PAW-devices or use other method to detect them<br /><br /> where NodeName has "PAW-" |
| Network_Backbone_Switch--tier0--SI          | Adjust IP segment/subnet for backbone<br /><br />let TargetSubnet = "192.168.1.0/24"; |
| Network_Backbone_Router--tier0--SI          | Adjust IP segment/subnet for backbone<br /><br />let TargetSubnet = "192.168.1.0/24"; |
| Network_Backbone_Management--tier0--SI      | Adjust IP segment/subnet for backbone<br /><br />let TargetSubnet = "192.168.1.0/24"; |
| Network_WLANAccessPoint--tier2--SI          | Filter option<br /><br /> where tostring(rawData.deviceSubtype) == "WLANAccessPoint" |
| Temp-Client-Devices--excluded--SI           | Filter devices that should be excluded using tag<br /><br /> where tostring(rawData.deviceType) == "Workstation"<br /> where NodeName startswith "fvf-"<br /> where NodeName !has "cloud" |



#### Sample query in Mode: TEST - Network_Backbone_Switch--tier0--SI

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



#### Testing Queries - Azure Resource Graph

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/TestingQueries-Azure.png)



#### Testing Queries - Defender

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/TestingQueries-Defender.png)



#### Defender: How can I validate & Show all tagged resources when I test ?

Find this line

```
| where array_index_of(AssetTagsArray, AssetTagName) == -1
```



Change to (add // in front)

```
// | where array_index_of(AssetTagsArray, AssetTagName) == -1
```



#### Azure: How can I validate & Show all tagged resources when I test ?

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
RunCriticalAssetTagging_Automation_Framework.ps1 -SCOPE TEST

Sample:
<Drive>:\SCRIPTS\SecurityInsights\RunCriticalAssetTagging_Automation_Framework.ps1 -SCOPE TEST
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
- Temp-Client-Devices--excluded--SI      <--this query is special as this query find resources that should be excluded (special tag)



This process takes a number of iterations and typically involves involvement of multiple teams and documentation, like naming conventions, ip plan, business systems overview

#### Example of custom query to backbone network switch

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

Not all systems in an organization are equally important. Assets are therefore classified into **4 criticality tiers**.

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/MDE-Criticality-Sample.png)

Not all types of resources in Defender Critical Asset Management supports 'Criticality Tier'. The tags are used in the risk model when native criticality data is not available.

| **Criticality Level** **(Defender)** | **Tier** | **Category**              | **Examples of systems**                                      |
| ------------------------------------ | -------- | ------------------------- | ------------------------------------------------------------ |
| Critical / Very high                 | Tier-0   | Identity Control          | Domain Controllers, Entra / Azure AD Sync, core  authentication systems |
| High                                 | Tier-1   | Privileged Infrastructure | Infrastructure servers, authentication systems,  management platforms |
| Medium                               | Tier-2   | Business Systems          | Employee workstations, application servers,  collaboration systems |
| Low                                  | Tier-3   | Low‑Trust Systems         | IoT devices, testing environments and specialized  systems   |

 

Assets are classified using 2 methods in Defender Critical Asset Management:

- **Automatic classification** “Predefined classifications”
- **Custom classification** using tags in Defender & Azure. 



![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/CriticalityLevel-Defender-overview.png)



**Custom classification in Defender Critical Asset Management**

- AzPlatformManagementResources--tier0--SI
- DomainControllerDNS--tier0--SI
- ADCertificateService--tier0--SI
- EntraSyncService--tier0--SI
- EmployeeWorkstations--tier2--SI
- EmployeeMobile--tier2--SI
- IoT--tier3--SI
- AzHubPlatformManagementSub--tier0--SI
- AzHubPlatformSecuritySub--tier0--SI
- AzLZDatacenterSub--tier0--SI
- AutomationServer--tier0--SI
- ServerBusinessServices--tier1--SI
- PAWDevices--tier0--SI
- Network_Backbone_Switch--tier0--SI
- Network_Backbone_Router--tier0--SI
- Network_Backbone_Management--tier0--SI
- Network_WLANAccessPoint--tier2--SI
- Temp-Client-Devices--excluded--SI



The tags are used in the risk model when native criticality data is not available.



### Step 4.1 - How to setup Criticality Tier Level against Azure resources ?

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/CriticalityLevel-Defender-Azure-tags.png)



NOTE: Adding a new Azure Tag takes between 24-48 hours before it will show up in Defender Critical Asset Management. This is due to syncing delays.



### Step 4.2 - How to setup Criticality Tier Level against Defender device resources ?

![](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Images/CriticalityLevel-Defender-MDE-tags.png)



### What am I missing in Critical Asset Management

| Area                      | What is missing ?                                            |
| ------------------------- | ------------------------------------------------------------ |
| Critical Asset Management | Ability to run Kusto query, instead of having to choose static field. Much more efficient and will also overcome limitations, where I can correlate tables<br /><br />Lots of field are missing like device roles, internal ip address |
| Critical Asset Management | API for onboarding of custom classifications. We have t manually create today |
| Device (custom query)     | Internal IP Address is not an option                         |
| Identity (custom query)   | Operator 'not contains' is missing<br /><br />Impossible to make a query like<br />Find all Admins that starts with Admin- AND doesn't contain ""-T0-T0-id" |
| Identity (custom query)   | extensionAttibute1-15 is missing<br /><br />Many tag users like<br />extensionAttribute6 (Classification) = Internal_User, Service_Account<br />extensionAttibute7 (AuthenticationMethod) = Internal_User_AD_Synced_MFA, Service_Account_Cloud_FIDO |

------



## Step 5: Run the Risk Analysis

The solution consists of three main components:

| Data collection (Input)                                      | Analysis                                                     | Reporting (Output)               |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------- |
| Microsoft Defender<br />Exposure Graph<br />Azure Resource Graph | Kusto queries<br />YAML report definitions<br />Risk score calculations | Excel reports<br />Summary Email |



## Files Overview (Risk Analysis)

| File Name                                                    | Purpose                                                      | Continues Updates via UpdateSecurityInsight-script |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| [RunSecurityInsight.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/RunSecurityInsight.ps1) | Engine Launcher<br />Includes parameters for starting risk analysis engine | No (custom file)                                   |
| [SecurityInsight_RiskAnalysis.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskAnalysis.ps1) | Main Engine <br />Engine file for Risk Analysis<br />Uses YAML-files as data repo<br />Uses RiskIndex-file to prioritize score | Yes <br />                                         |
| [SecurityInsight_RiskIndex.csv](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskIndex.csv) | Risk Index data file                                         | No (*)<br />(custom priority file)                 |
| [SecurityInsight_RiskAnalysis_Queries_Custom.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskAnalysis_Queries_Custom.yaml) | Report data file (custom tags)<br />Kusto queries against graph-engine | No <br />(custom queries)                          |
| [SecurityInsight_RiskAnalysis_Queries_Locked.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskAnalysis_Queries_Locked.yaml) | Report data file (recommended tags)<br />Kusto queries against graph-engine | Yes                                                |

(*) If you don't make custom changes in RiskIndex file, you can add the file into UpdateSecurityInsight.ps1 script to subscribe to my recommendations in priority.



### Step 5.1. Adjust the authentication + smtp details in launcher file, RunSecurityInsight.ps1

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

        # Consider to use an Azure Keyvault and retrieve credentials from there !
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



### Step 5.3B. Run Risk Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1 to deploy AI instance

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

        // Step 1  Build asset list and attach metadata used later in joins and scoring
        // Only endpoints are included
        // Excluded endpoints are removed
        // Customer facing flag is normalized from rawData or raw
        // Existing criticality fields are kept exactly as-is
        // Asset tags are collected from multiple rawData locations and combined into one list
        // AssetTags is the semicolon separated tag string
        // AssetTierByTag is extracted from AssetTags using regex and sorted for stable output
        // LegacyEndOfSupport is derived from AssetProps rawData OS platform and version fields when present
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
            | extend _TierTags = extract_all(@"([^;]*--tier[0-3]--SI[^;]*)", AssetTags)
            | extend AssetTierByTag = strcat_array(array_sort_asc(coalesce(_TierTags, dynamic([]))), ";")
            | extend NodeAssetTags = _AllTags
            
            // Exclude Devices, which includes tag with '--Excluded--SI'
            | where AssetTags !has "--Excluded--SI"
            
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
        // Each node can have multiple categories so Categories is expanded to one row per category
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
        // Only edges whose label contains affecting are included
        // Edge properties are included when present otherwise an empty object is used
        let Edges =
            ExposureGraphEdges
            | where tostring(EdgeLabel) contains "affecting"
            | extend EdgeProps = column_ifexists("EdgeProperties", dynamic({}))
            | project SourceNodeId, TargetNodeId, EdgeLabel, EdgeProps;

        // Step 4  Relate assets and findings using edges
        // Edges can point in either direction so both directions are joined and then unioned
        // The result is summarized per AssetName AssetLabel FindingName to de-duplicate
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
        // (DeviceKey already carried forward via Option A fix)

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



### Example of Query - Device_Missing_CVEs_Detailed_BucketFilter

```
    - ReportName: Device_Missing_CVEs_Detailed_BucketFilter
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
      - AssetName
      - AssetLabel
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
      - AadDeviceId
      - CVELastModified
      - CVSSDesc
      - CVE_ID
      - CriticalityRuleBased
      - CriticalityRuleNames
      - CriticalityLevel
      - AssetTierByTag
      - AssetTags
      SortBy:
      - RiskScoreTotal
      ReportQuery:
      - |
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

        // Step 5  De-duplicate asset to finding rows and merge edge properties
        // One row per AssetName AssetLabel FindingName is kept
        // Edge labels and edge properties across duplicates are combined
        AF_edges
        | summarize
            EdgeLabels           = make_set(EdgeLabel),
            EdgePropsAll         = make_bag(EdgeProps),
            FindingLabel         = any(FindingLabel),
            FindingCategories    = any(FindingCategories),
            FindingProps         = any(FindingProps),
            AssetProps           = any(AssetProps),
            CriticalityLevel     = any(CriticalityLevel),
            CriticalityRuleBased = any(CriticalityRuleBased),
            CriticalityRuleNames = any(CriticalityRuleNames),
            AadDeviceId          = any(AadDeviceId),
            EG_IsCustomerFacing  = any(EG_IsCustomerFacing),
            EG_IsExcluded        = any(EG_IsExcluded),
            NodeAssetTags        = any(NodeAssetTags),
            AssetTags            = any(AssetTags),
            AssetTierByTag       = any(AssetTierByTag),
            LegacyEndOfSupport   = any(LegacyEndOfSupport)
          by AssetName, AssetLabel, FindingName

        // Step 6  Build a unified Properties bag for simpler lookups
        // finding holds the full finding node properties
        // raw holds rawData if present otherwise an empty object
        // edge holds combined edge properties from all related edges
        | extend Properties =
            bag_merge(
                bag_pack("finding", FindingProps),
                bag_pack("raw", iif(isnull(FindingProps.rawData), dynamic({}), FindingProps.rawData)),
                bag_pack("edge", EdgePropsAll)
            )

        // Step 7  Extract scoring fields and filter to CVE findings
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

        // Step 8  Compute criticality tier with fallback to tier tags
        // CriticalityLevel is preferred when present
        // When CriticalityLevel is missing tier tags are mapped to a numeric tier
        // When both are missing tier 3 is used as default
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

        // Step 9  Set fixed domain and category values for this dataset
        | extend SecurityDomain = "Endpoint"
        | extend ConfigurationId = "CVE"
        | extend Category    = "Vulnerabilities"
        | extend Subcategory = "CVEs (Missing Updates)"

        // Step 10  Filter by CVE last modified date
        | extend CVELastModified = todatetime(coalesce(Properties.finding.raw.lastModifiedDate, Properties.raw.lastModifiedDate))
        | where CVELastModified < ago(40d)

        // Step 11  Extract exploit related flags from finding rawData and raw
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

        // Step 12  Compute risk factor fields at row level and provide detailed strings
        // RiskFactor_Consequence is defaulted to 0
        // RiskFactor_Probability is a 0 to 3 score
        // Add 1 when any exploit signal is present
        // Add 1 when the asset is customer facing
        // Add 1 when the asset is legacy end-of-support
        // RiskFactor_Probability_Detailed and RiskFactor_Probability_DetailedScore are semicolon separated strings
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

        // Step 13  Extra safety filter to ensure excluded assets do not appear
        | where EG_IsExcluded == false

        // Step 14  Bucket filter support
        // DeviceKey is used for bucket filtering and distinct counting
        | extend DeviceKey = iif(isnotempty(AadDeviceId), AadDeviceId, AssetName)
        __BUCKET_FILTER__

        // Step 15  Final projection and ordering for detailed output
        | project
            SecurityDomain,
            Category,
            Subcategory,
            AssetName,
            AssetLabel,
            AadDeviceId,
            EG_IsCustomerFacing,
            EG_IsExcluded,

            ConfigurationName = FindingName,
            CVE_ID = FindingLabel,
            ConfigurationId,

            CriticalityLevel,
            CriticalityRuleBased,
            CriticalityRuleNames,
            CriticalityTier,
            CriticalityTierLevel,

            AssetTierByTag,
            AssetTags,
            LegacyEndOfSupport,

            Impact,
            SecuritySeverity,
            CVELastModified,

            HasExploit,
            IsExploitVerified,
            IsInExploitKit,
            IsZeroDay,

            RiskFactor_Consequence,
            RiskFactor_Probability,
            RiskFactor_Probability_Detailed,
            RiskFactor_Probability_DetailedScore,

            CVSSDesc = tostring(coalesce(
                Properties.finding.rawData.description,
                Properties.raw.description,
                Properties.finding.raw.description
            )),
            AssetProps,
            Properties
        | order by CriticalityTier asc, Impact desc, AssetName asc, CVE_ID asc

```



### Example of Query - Attack_Paths_Detailed_BucketFilter_Identity_Group_Membership_to_Privileged_Resources

```
    - ReportName: Attack_Paths_Detailed_BucketFilter_Identity_Group_Membership_to_Privileged_Resources
      ReportPurpose: Identify identities that are members of groups and where those groups have permissions or roles on privileged
        Azure targets. Enrich each path with the standard node context and prioritize by the business impact of the FINAL TARGET.
      SecurityDomain: Azure
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
      - AssetName
      - AssetLabel
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
      SortBy:
      - RiskScoreTotal
      ReportQuery:
      - |
        // =================================================================================================
        // REPORT  Group membership privilege paths to Azure resources using Exposure Graph
        // =================================================================================================
        //
        // Report purpose
        // Identify identities that are members of groups and where those groups have permissions or roles on
        // privileged Azure targets. Enrich each path with the standard node context and prioritize by the
        // business impact of the FINAL TARGET.
        //
        // Interpretation guard and priority rules
        // - Priority is driven by the TARGET criticality tier first
        // - Then by tier escalation where source tier is higher than target tier
        // - Then by internet exposure where target exposure is weighted higher than source exposure
        // - The source identity matters as an amplifier but the target drives the priority
        //
        // Output description detailed rows
        // One row per unique path
        // Identity -> Group -> Target
        // Enriched with
        // - IsInternetExposed for source and target
        // - AssetTierByTag for source and target
        // - LegacyEndOfSupport for source and target
        // - RiskFactor probability fields including detailed breakdown for source and target
        // - AttackPathPriorityScore components and mapped severity label
        // - Human readable AttackPath and AttackPathDetailed strings
        //
        // Query steps overview
        // Step 0  Define legacy operating system reference lists
        // Step 1  Build Nodes catalog as enrichment backbone using standard context fields
        // Step 2  Find identities in groups and de duplicate to a stable group membership grain
        // Step 3  Find group permissions or roles on Azure targets
        // Step 4  Assemble Identity -> Group -> Target paths and de duplicate
        // Step 5  Enrich source identity and target using Nodes catalog
        // Step 6  Apply standard prioritization logic and build attack path strings
        // Step 7  Project detailed output columns and apply ordering
        // =================================================================================================

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

        // Step 1  Build node catalog used to enrich attack paths
        let Nodes =
            ExposureGraphNodes
            | extend CategoriesStr = tolower(tostring(Categories))
            | extend NodeNameNorm  = coalesce(NodeName, tostring(EntityIds[0].id), tostring(NodeId))
            | extend RawData = todynamic(NodeProperties).rawData
            | extend Raw     = todynamic(todynamic(NodeProperties).raw)
            | extend AadDeviceId =
                tostring(coalesce(
                    RawData.aadDeviceId,
                    Raw.aadDeviceId,
                    NodeProperties.aadDeviceId
                ))

            | extend DeviceKey = iif(isnotempty(AadDeviceId), AadDeviceId, NodeNameNorm)
            __BUCKET_FILTER__

            | extend CriticalityLevel =
                toint(coalesce(
                    tostring(NodeProperties.criticalityLevelProps[0].criticalityLevel),
                    tostring(NodeProperties.rawData.criticalityLevel.criticalityLevel),
                    tostring(NodeProperties.criticalityLevel.criticalityLevel)
                ))
            | extend CriticalityRuleBased =
                toint(coalesce(
                    tostring(NodeProperties.criticalityLevelProps[0].ruleBasedCriticalityLevel),
                    tostring(NodeProperties.rawData.criticalityLevel.ruleBasedCriticalityLevel),
                    tostring(NodeProperties.criticalityLevel.ruleBasedCriticalityLevel)
                ))
            | extend CriticalityRuleNames =
                coalesce(
                    strcat_array(NodeProperties.criticalityLevelProps[0].ruleNames, ", "),
                    strcat_array(NodeProperties.rawData.criticalityLevel.ruleNames, ", "),
                    ""
                )

            | extend IsInternetExposed =
                tobool(coalesce(
                    NodeProperties.rawData.isCustomerFacing,
                    NodeProperties.raw.isCustomerFacing,
                    false
                ))

            | extend IsExcluded =
                tobool(coalesce(
                    NodeProperties.rawData.isExcluded,
                    NodeProperties.raw.isExcluded,
                    false
                ))

            | extend RawData = todynamic(NodeProperties).rawData
            | extend Raw     = todynamic(todynamic(NodeProperties).raw)

            | extend tagsBag1 = todynamic(coalesce(RawData.tags, dynamic({})))
            | extend tagsBag2 = todynamic(coalesce(todynamic(NodeProperties).tags, dynamic({})))
            | extend tagsBag3 = todynamic(coalesce(Raw.tags, dynamic({})))

            | extend AssetTierFromBag = tostring(coalesce(
                tagsBag1.AssetTier, tagsBag2.AssetTier, tagsBag3.AssetTier,
                tagsBag1["AssetTier--SI"], tagsBag2["AssetTier--SI"], tagsBag3["AssetTier--SI"]
            ))

            | extend deviceManualTags  = iff(isnull(RawData.deviceManualTags),  dynamic([]), todynamic(RawData.deviceManualTags))
            | extend deviceDynamicTags = iff(isnull(RawData.deviceDynamicTags), dynamic([]), todynamic(RawData.deviceDynamicTags))
            | extend tagsArray1        = iff(isnull(RawData.tags.tags),         dynamic([]), todynamic(RawData.tags.tags))

            | extend _AllTags          = array_concat(array_concat(deviceManualTags, deviceDynamicTags), tagsArray1)
            | extend AssetTags         = strcat_array(_AllTags, ";")
            
            // Exclude Devices, which includes tag with '--Excluded--SI'
            | where AssetTags !has "--Excluded--SI"
            
            | extend _TierTagsFromText = extract_all(@"([^;]*--tier[0-3]--SI[^;]*)", AssetTags)

            | extend AssetTierByTag =
                case(
                    isnotempty(AssetTierFromBag), AssetTierFromBag,
                    array_length(_TierTagsFromText) > 0, strcat_array(array_sort_asc(_TierTagsFromText), ";"),
                    ""
                )

            | extend CriticalityTierFromTag =
                case(
                    AssetTierByTag has "--tier0--SI" or tolower(AssetTierByTag) has "tier0" or AssetTierByTag == "0", 0,
                    AssetTierByTag has "--tier1--SI" or tolower(AssetTierByTag) has "tier1" or AssetTierByTag == "1", 1,
                    AssetTierByTag has "--tier2--SI" or tolower(AssetTierByTag) has "tier2" or AssetTierByTag == "2", 2,
                    AssetTierByTag has "--tier3--SI" or tolower(AssetTierByTag) has "tier3" or AssetTierByTag == "3", 3,
                    int(null)
                )

            | extend CriticalityTier = toint(coalesce(CriticalityLevel, CriticalityTierFromTag, 3))
            | extend CriticalityTierLevel =
                case(
                    CriticalityTier == 0, "Critical - tier 0",
                    CriticalityTier == 1, "High - tier 1",
                    CriticalityTier == 2, "Medium - tier 2",
                    "Low - tier 3"
                )

            | extend AssetOSPlatform =
                tostring(coalesce(RawData.osPlatform, RawData.OSPlatform, RawData.platform, RawData.operatingSystem, RawData.os))
            | extend AssetOSVersion =
                tostring(coalesce(RawData.osVersion, RawData.OSVersion, RawData.version, RawData.operatingSystemVersion))
            | extend AssetOSDistribution =
                tostring(coalesce(RawData.osDistribution, RawData.OSDistribution, RawData.distribution))
            | extend MacMajor = toint(extract(@"^(\d+)", 1, AssetOSVersion))

            | extend IsLegacyWindows = iff(AssetOSPlatform in~ (LegacyWindowsOSPlatforms), 1, 0)
            | extend IsLegacyMacOS   = iff(tolower(AssetOSPlatform) has "mac" and MacMajor in~ (LegacyMacOSMajorVersions), 1, 0)
            | extend IsLegacyLinux   = iff(
                    tolower(AssetOSPlatform) has "linux"
                    and (AssetOSDistribution has_any (LegacyLinuxMatchers) or AssetOSVersion has_any (LegacyLinuxMatchers)),
                    1, 0
                )
            | extend LegacyEndOfSupport = iff(IsLegacyWindows == 1 or IsLegacyMacOS == 1 or IsLegacyLinux == 1, 1, 0)

            | extend RiskFactorsArray =
                todynamic(coalesce(
                    NodeProperties.rawData.risk.riskFactors,
                    NodeProperties.risk.riskFactors,
                    dynamic([])
                ))
            | extend RiskFactorsArray = iff(isnull(RiskFactorsArray), dynamic([]), RiskFactorsArray)

            | mv-apply rf = RiskFactorsArray on (
                where isnotempty(trim(" ", tostring(rf)))
                | summarize RiskFactorSet = make_set(tostring(rf))
            )
            | extend RiskFactorSet = coalesce(RiskFactorSet, dynamic([]))
            | extend RF_P_RiskFactorsCount = array_length(RiskFactorSet)
            | extend RF_P_InternetExposed  = iff(IsInternetExposed == true, 1, 0)
            | extend RF_P_LegacyEoS        = iff(LegacyEndOfSupport == 1, 1, 0)

            | extend RiskFactor_Probability = RF_P_RiskFactorsCount + RF_P_InternetExposed + RF_P_LegacyEoS
            | extend RiskFactor_Consequence = 0

            | extend RiskFactor_Probability_Detailed =
                strcat_array(
                    array_sort_asc(
                        array_concat(
                            RiskFactorSet,
                            iff(RF_P_InternetExposed == 1, dynamic(["Internet-Exposed"]), dynamic([])),
                            iff(RF_P_LegacyEoS == 1, dynamic(["LegacyEndOfSupport"]), dynamic([]))
                        )
                    ),
                    ";"
                )

            | mv-apply rf = array_concat(
                    RiskFactorSet,
                    iff(RF_P_InternetExposed == 1, dynamic(["Internet-Exposed"]), dynamic([])),
                    iff(RF_P_LegacyEoS == 1, dynamic(["LegacyEndOfSupport"]), dynamic([]))
                ) on (
                where isnotempty(trim(" ", tostring(rf)))
                | summarize ScoreParts = make_set(strcat(tostring(rf), "=1"))
            )
            | extend RiskFactor_Probability_DetailedScore =
                strcat_array(array_sort_asc(coalesce(ScoreParts, dynamic([]))), ";")

            | project
                NodeId,
                NodeName          = NodeNameNorm,
                NodeLabel,
                Categories        = CategoriesStr,
                NodeProperties,
                CriticalityLevel,
                CriticalityTier,
                CriticalityTierLevel,
                CriticalityRuleBased,
                CriticalityRuleNames,
                IsInternetExposed,
                IsExcluded,
                AssetTags,
                AssetTierByTag,
                LegacyEndOfSupport,
                RiskFactorsArray,
                RiskFactor_Probability,
                RiskFactor_Probability_Detailed,
                RiskFactor_Probability_DetailedScore,
                RiskFactor_Consequence;

        // Step 2  Find identities in groups and de duplicate
        let IdentityGroupMembership =
            ExposureGraphEdges
            | where EdgeLabel == "member of"
            | where SourceNodeLabel in ("user", "serviceprincipal", "managedidentity")
            | where TargetNodeLabel == "group"
            | project
                IdentityNodeId    = SourceNodeId,
                IdentityNodeName  = SourceNodeName,
                IdentityNodeLabel = SourceNodeLabel,
                GroupNodeId       = TargetNodeId,
                GroupNodeName     = TargetNodeName
            | summarize
                Identities        = make_set(IdentityNodeName),
                IdentityTypes     = make_set(IdentityNodeLabel),
                IdentityCount     = dcount(IdentityNodeId),
                FirstIdentityId   = any(IdentityNodeId),
                FirstIdentityName = any(IdentityNodeName),
                FirstIdentityLabel= any(IdentityNodeLabel)
              by GroupNodeId, GroupNodeName;

        // Step 3  Find group permissions or roles on Azure targets
        let GroupAccessToTargets =
            ExposureGraphEdges
            | where EdgeLabel in ("has role on", "has permissions to")
            | where SourceNodeLabel == "group"
            | where TargetNodeLabel in (
                "subscriptions",
                "resourcegroups",
                "microsoft.keyvault/vaults",
                "microsoft.storage/storageaccounts",
                "microsoft.sql/servers",
                "microsoft.compute/virtualmachines",
                "microsoft.cognitiveservices/accounts"
            )
            | project
                GroupNodeId      = SourceNodeId,
                EdgeLabel        = EdgeLabel,
                FinalTargetId    = TargetNodeId,
                FinalTargetName  = TargetNodeName,
                FinalTargetLabel = TargetNodeLabel;

        // Step 4  Assemble Identity -> Group -> Target paths and de duplicate
        let Paths =
            IdentityGroupMembership
            | join kind=inner (GroupAccessToTargets) on GroupNodeId
            | summarize
                Identities         = any(Identities),
                IdentityTypes      = any(IdentityTypes),
                IdentityCount      = any(IdentityCount),
                FirstIdentityId    = any(FirstIdentityId),
                FirstIdentityName  = any(FirstIdentityName),
                FirstIdentityLabel = any(FirstIdentityLabel),
                GroupNodeName      = any(GroupNodeName),
                EdgeLabel          = any(EdgeLabel),
                FinalTargetName    = any(FinalTargetName),
                FinalTargetLabel   = any(FinalTargetLabel)
              by FinalTargetId, GroupNodeId;

        // Step 5-7  Enrich source and target and apply standard prioritization logic
        Paths
        | join kind=leftouter (
            Nodes
            | project-rename
                SourceNodeId                = NodeId,
                SourceNodeName              = NodeName,
                SourceNodeLabel             = NodeLabel,
                SourceCriticalityTier       = CriticalityTier,
                SourceCriticalityTierLevel  = CriticalityTierLevel,
                SourceIsInternetExposed     = IsInternetExposed,
                SourceIsExcluded            = IsExcluded,
                SourceAssetTierByTag        = AssetTierByTag,
                SourceLegacyEndOfSupport    = LegacyEndOfSupport,
                SourceRiskProb              = RiskFactor_Probability,
                SourceRiskProbDetailed      = RiskFactor_Probability_Detailed,
                SourceRiskProbDetailedScore = RiskFactor_Probability_DetailedScore,
                SourceNodeProperties        = NodeProperties
        ) on $left.FirstIdentityId == $right.SourceNodeId

        | join kind=leftouter (
            Nodes
            | project-rename
                TargetNodeId                = NodeId,
                TargetNodeName              = NodeName,
                TargetNodeLabel             = NodeLabel,
                TargetCriticalityTier       = CriticalityTier,
                TargetCriticalityTierLevel  = CriticalityTierLevel,
                TargetCriticalityRuleBased  = CriticalityRuleBased,
                TargetCriticalityRuleNames  = CriticalityRuleNames,
                TargetIsInternetExposed     = IsInternetExposed,
                TargetIsExcluded            = IsExcluded,
                TargetAssetTierByTag        = AssetTierByTag,
                TargetLegacyEndOfSupport    = LegacyEndOfSupport,
                TargetRiskProb              = RiskFactor_Probability,
                TargetRiskProbDetailed      = RiskFactor_Probability_Detailed,
                TargetRiskProbDetailedScore = RiskFactor_Probability_DetailedScore,
                TargetNodeProperties        = NodeProperties
        ) on $left.FinalTargetId == $right.TargetNodeId

        // Step 6  Attack path prioritization logic
        | extend TierEscalation =
            case(
                isnotempty(SourceCriticalityTier) and isnotempty(TargetCriticalityTier) and SourceCriticalityTier > TargetCriticalityTier,
                    SourceCriticalityTier - TargetCriticalityTier,
                0
            )
        | extend IsLateralMovement = TierEscalation > 0
        | extend LateralMovementType =
            case(
                TierEscalation >= 3, "Privilege escalation large tier jump",
                TierEscalation == 2, "Privilege escalation two tiers",
                TierEscalation == 1, "Privilege escalation one tier",
                "Direct access same tier"
            )

        | extend TargetTierWeight =
            case(
                TargetCriticalityTier == 0, 100,
                TargetCriticalityTier == 1, 60,
                TargetCriticalityTier == 2, 30,
                10
            )
        | extend EscalationWeight = TierEscalation * 10
        | extend ExposureWeight   = iff(TargetIsInternetExposed == true, 8, 0) + iff(SourceIsInternetExposed == true, 3, 0)
        | extend SourceTierAmplifier =
            case(
                SourceCriticalityTier == 0, 8,
                SourceCriticalityTier == 1, 5,
                SourceCriticalityTier == 2, 2,
                0
            )
        | extend AttackPathPriorityScore = TargetTierWeight + EscalationWeight + ExposureWeight + SourceTierAmplifier

        | extend AttackPathPriority =
            case(
                AttackPathPriorityScore >= 120, "Critical",
                AttackPathPriorityScore >= 90,  "Very High",
                AttackPathPriorityScore >= 60,  "High",
                AttackPathPriorityScore >= 30,  "Medium-High",
                AttackPathPriorityScore >= 15,  "Medium",
                "Low"
            )

        // Step 7  Human readable paths
        | extend InternetExposureTarget = iff(TargetIsInternetExposed == true, "Internet-Exposed", "Not Internet-Exposed")
        | extend InternetExposureSource = iff(SourceIsInternetExposed == true, "Internet-Exposed", "Not Internet-Exposed")

        | extend AttackPath =
            strcat(
                FirstIdentityLabel, " [", FirstIdentityName, "] -> ",
                "group [", GroupNodeName, "] -> ",
                TargetNodeLabel, " [", FinalTargetName, "]"
            )

        | extend AttackPathDetailed =
            strcat(
                "SOURCE ", FirstIdentityLabel, " [", FirstIdentityName, "] ",
                "tier ", tostring(SourceCriticalityTier), " ", tostring(SourceCriticalityTierLevel), " | ", InternetExposureSource,
                iff(IdentityCount > 1, strcat(" | + ", tostring(IdentityCount - 1), " other identity/ies"), ""),
                " -> GROUP [", GroupNodeName, "] ",
                " -> TARGET ", TargetNodeLabel, " [", FinalTargetName, "] ",
                "tier ", tostring(TargetCriticalityTier), " ", tostring(TargetCriticalityTierLevel), " | ", InternetExposureTarget,
                " | escalation ", tostring(TierEscalation),
                " | ", LateralMovementType
            )

        | extend SecurityDomain = "Azure"
        | extend Category = "Attack Paths"
        | extend SubCategory = "GroupMembershipPrivilege"
        | extend ConfigurationName = tostring(LateralMovementType)
        | extend ConfigurationId = "group_membership"

        | project
            SecurityDomain,
            Category,
            SubCategory,
            ConfigurationName,
            ConfigurationId,

            AttackPathPriority,
            AttackPathPriorityScore,
            TierEscalation,
            IsLateralMovement,
            LateralMovementType,
            EscalationWeight,
            ExposureWeight,

            GroupNodeId,
            GroupNodeName,
            EdgeLabel,

            FirstIdentityId,
            FirstIdentityName,
            FirstIdentityLabel,
            TotalIdentitiesInGroup = IdentityCount,
            AllIdentities = Identities,
            IdentityTypes,

            FinalTargetId,
            FinalTarget = FinalTargetName,
            FinalTargetType = FinalTargetLabel,

            TargetCriticalityTier,
            TargetCriticalityTierLevel,
            TargetCriticalityRuleBased,
            TargetCriticalityRuleNames,

            TargetAssetTierByTag,
            TargetIsInternetExposed,
            TargetLegacyEndOfSupport,
            TargetRiskProb,
            TargetRiskProbDetailed,
            TargetRiskProbDetailedScore,

            SourceCriticalityTier,
            SourceCriticalityTierLevel,
            SourceAssetTierByTag,
            SourceIsInternetExposed,
            SourceLegacyEndOfSupport,
            SourceRiskProb,
            SourceRiskProbDetailed,
            SourceRiskProbDetailedScore,

            AttackPath,
            AttackPathDetailed,

            SourceNodeProperties,
            TargetNodeProperties

        | order by AttackPathPriorityScore desc, TierEscalation desc, TargetCriticalityTier asc, FinalTarget asc

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

