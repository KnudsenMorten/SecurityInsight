# SecurityInsight
Rethink Secure Score into a new risk-based security risk score, based on consequence, probability and risk factors. Solution includes critical asset tagging, ready-to-use reports (based on Defender Exposure Graph and Azure Resource Graphs), automation-scripts, risk index and more



## Introduction

Modern organizations operate complex IT environments consisting of cloud resources, endpoints, identities and infrastructure systems.

Security platforms continuously generate large volumes of security data including vulnerabilities, configuration issues, security recommendations and exposure analysis.

While these tools are effective at identifying security problems, prioritization remains a significant challenge.

 

## Challenges with Traditional Vulnerability Prioritization

Traditional vulnerability management often focuses on CVSS scores or severity classifications.

 

This approach creates several challenges:

·     the same vulnerability is evaluated equally regardless of the asset

·     business impact is not considered

·     attack chains and relationships are not identified.

 

## Exposure Graph Architecture

The Security Insight framework uses data from Microsoft Defender Exposure Graph including:

·     ExposureGraphNodes

·     ExposureGraphEdges

·     Defender Vulnerability Management findings

·     configuration assessments

 

These datasets allow analysis of relationships between systems and security findings.

 

## Asset Classification

Assets are automatically classified using tagging rules based on system roles.

 

Examples include:

·     Domain Controllers

·     Entra synchronization services

·     employee devices

·     IoT devices

 

These classifications are translated into tier tags such as:

·     --tier0--SI

·     --tier1--SI

·     --tier2--SI

·     --tier3--SI

 

The tags are used in the risk model when native criticality data is not available.



## Risk Score Model

Risk Score is calculated using two dimensions:

**Consequence Score** – the potential impact if exploitation occurs.

**Probability Score** – the likelihood of exploitation based on asset tier and exposure context.

 

## Risk Factors

Probability Score may be adjusted using contextual risk indicators such as:

·     exploit availability

·     internet exposure

·     legacy systems

 

These factors increase the likelihood of exploitation.

 

## Risk Calculation

The final risk score is calculated as:

**Risk Score = Consequence Score × Probability Score**

This score is used to prioritize remediation activities.

 

## Reporting

The framework generates both summary and detailed reports.

 

Summary reports include:

·     number of findings per tier

·     overall risk levels

·     configuration status

 

Detailed reports include affected assets, vulnerability identifiers and remediation guidance.

 

## Implementation Architecture

The solution consists of three main components:

 

#### Data Collection

·     Microsoft Defender

·     Exposure Graph

·     Azure Resource Graph

 

#### Analysis

·     Kusto queries

·     YAML report definitions

·     risk score calculations

 

#### Output

·     Excel reports

·     dashboards

·     prioritized remediation lists.

 

## Governance and Compliance

The model supports several regulatory and security frameworks including:

·     NIS2 Directive

·     CIS Critical Security Controls

·     ISO 27001 risk management principles.

 

## Operational Benefits

Organizations implementing the model gain:

·     improved vulnerability prioritization

·     reduced remediation backlog

·     improved visibility into attack paths.

 

## Future Opportunities

Potential future developments include:

·     automated attack path analysis

·     integration with threat intelligence

·     integration with ticketing and risk management platforms.

 

## Transparency and Flexibility

The Security Insight architecture is fully open and transparent and is based on:

 

·     PowerShell automation

·     Kusto Queries for data analysis

·     CSV files defining scoring models

·     YAML report definitions

·     asset tagging

 

This ensures the prioritization model can be inspected, validated and adapted to organizational requirements.

 

## Collaboration with Microsoft

The development of the Security Insight model is conducted in close dialogue with Microsoft.

Morten Knudsen collaborates with Microsoft, including Raviv Tamir, Corporate Vice President for Microsoft Defender, and his team to explore how the risk‑based prioritization concepts can influence the future strategy of the Microsoft Defender platform.

