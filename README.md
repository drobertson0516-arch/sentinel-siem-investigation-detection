# Microsoft Sentinel-Style SIEM Investigation & Detection

## Project Overview

This project demonstrates a simulated Security Operations Center (SOC) investigation involving suspicious authentication activity, Microsoft 365 account compromise, sensitive data access, and external email forwarding.

Acting as a Tier 1 SOC analyst for the fictional organization Northstar Financial Services, I investigated a Microsoft Sentinel-style alert involving 11 failed authentication attempts followed by a successful sign-in from an unusual source IP, geographic location, and unmanaged device.

The investigation expanded beyond the initial authentication alert to determine the scope and impact of the unauthorized session. Synthetic Microsoft 365 and SharePoint telemetry was analyzed to identify mailbox activity, file downloads, access to financial information, and the creation of an unauthorized external mailbox forwarding rule.

The project also includes Microsoft Sentinel-style KQL queries and detection logic designed to identify similar failed-authentication-followed-by-success patterns while considering potential false positives.

> **Training Disclaimer:** This project uses synthetic telemetry in a Microsoft Sentinel-style environment for cybersecurity training and portfolio purposes. No production systems, real customer data, or live Microsoft Sentinel tenant were used.

## Investigation Objectives

The investigation was designed to answer the following questions:

- Was the suspicious authentication consistent with the user's normal behavior?
- Was the source IP associated with other users in the available telemetry?
- Did the authentication originate from a known and managed device?
- What activity occurred after the successful authentication?
- What sensitive information was accessed or downloaded?
- Was organizational data disclosed externally?
- What containment and escalation actions were appropriate?
- How could similar authentication behavior be detected in the future?

## Incident Summary

The investigation began with a Medium-severity alert involving the account `mlopez@northstarfinancial.com`.

### Initial Alert Indicators

- **Failed Sign-ins:** 11
- **Successful Sign-ins:** 1
- **Source IP:** `45.83.64.19`
- **Location:** Amsterdam, Netherlands
- **Device:** Unknown, unmanaged Linux device
- **Time Window:** Approximately 8:31 AM–8:44 AM
- **Initial Severity:** Medium

Recent successful authentication activity for M. Lopez originated from `10.24.18.56` in Orlando, US, using the managed Windows 11 device `NFS-LT-0442`.

The combination of repeated failed authentication attempts, a subsequent successful authentication, a previously unobserved source IP and location, and an unknown unmanaged device increased suspicion and led to further investigation.

## Key Findings

Post-authentication analysis identified the following activity:

- Microsoft Exchange Online was accessed shortly after the suspicious login.
- The mailbox was searched for financial information.
- Emails related to vendor payments and payroll were opened.
- Vendor payment and employee payroll attachments were downloaded.
- SharePoint and the Finance/Accounts Payable folder were accessed.
- `Vendor_Banking_Information.xlsx`, containing full vendor routing and bank account numbers, was downloaded.
- An unauthorized external mailbox forwarding rule was created.
- Six organizational emails were confirmed as forwarded to an external address.
- Forwarded messages included an accounts-payable approval request and a vendor bank-change request.

Based on the confirmed account compromise, access to sensitive financial information, and external disclosure of organizational email, the incident severity was escalated from **Medium to High**.

Available evidence did not establish that a fraudulent payment occurred or that the downloaded SharePoint data was subsequently transferred through another exfiltration mechanism.

## Investigation Methodology

The investigation followed a structured SOC workflow that moved from alert triage to authentication analysis, scope determination, impact assessment, containment, and detection engineering.

### 1. Establish User Authentication Baseline

Recent authentication activity for M. Lopez was reviewed to identify normal source IP addresses, geographic locations, devices, and sign-in patterns.

The baseline showed recent successful authentication from a managed Windows 11 corporate device in Orlando, while the suspicious authentication originated from an unknown, unmanaged Linux device in Amsterdam.

### 2. Investigate the Suspicious Source IP

Authentication activity associated with `45.83.64.19` was reviewed to determine whether the source IP appeared elsewhere in the available telemetry.

Within the synthetic dataset, the IP was associated only with the suspicious activity involving M. Lopez.

### 3. Analyze Device Context

Device information associated with the suspicious authentication was compared against the user's recent baseline.

The suspicious session originated from an unknown, unmanaged Linux device rather than the managed Windows 11 device observed during recent legitimate activity.

### 4. Investigate Post-Authentication Activity

Microsoft 365 and SharePoint activity was reviewed to determine what occurred after the successful authentication.

The investigation identified mailbox searches, email access, attachment downloads, SharePoint access, sensitive financial data access, and creation of an external mailbox forwarding rule.

### 5. Determine Scope and Impact

Downloaded documents and externally forwarded messages were reviewed to determine the type and sensitivity of information involved.

The investigation confirmed exposure of internal business information, employee PII and payroll information, vendor banking information, and organizational email.

### 6. Contain and Escalate

The compromised account was disabled, active sessions were revoked, credentials were reset, and evidence associated with the unauthorized forwarding rule was preserved before the rule was removed.

The incident was escalated to appropriate security, Finance, Legal/Compliance, incident response, and business stakeholders.

## KQL Investigation Queries

The project includes Microsoft Sentinel-style KQL queries representing different stages of the investigation:

| Query | Purpose |
|---|---|
| `01-user-baseline.kql` | Establish the affected user's recent authentication baseline |
| `02-source-ip-investigation.kql` | Investigate activity associated with the suspicious source IP |
| `03-device-investigation.kql` | Compare suspicious device information against recent authentication activity |
| `04-forwarding-analysis.kql` | Analyze and summarize external mailbox forwarding activity |
| `05-failed-then-success-detection.kql` | Detect repeated failed sign-ins followed by successful authentication |

### Detection Logic

The final detection query was designed to identify:

- Five or more failed authentication attempts
- Same user and source IP
- Activity within a 15-minute window
- Successful authentication occurring after the failed attempts
- Unmanaged device **OR** unusual geographic location

The five-attempt threshold was selected as a starting point to balance detection sensitivity with potential false positives.

Potential legitimate causes such as corporate VPN usage, approved travel, password-entry mistakes, known network addresses, and authorized temporary devices should be considered during alert triage.

> **Schema Note:** The KQL files represent Microsoft Sentinel-style investigation and detection logic for this synthetic training project. The included CSV evidence uses a simplified portfolio schema, while production Microsoft Sentinel and Microsoft Entra data may use different field structures and data types. The queries therefore demonstrate the investigation logic and KQL concepts rather than claiming direct execution against the included CSV files or a live tenant.


## MITRE ATT&CK Mapping

Observed activity was mapped to MITRE ATT&CK based on the behaviors supported by the available evidence.

| Technique | Name | Observed Behavior |
|---|---|---|
| `T1110` | Brute Force | Repeated password attempts occurred before the successful authentication |
| `T1114` | Email Collection | The compromised mailbox was searched, emails were opened, and attachments were downloaded |
| `T1114.003` | Email Forwarding Rule | An unauthorized forwarding rule sent organizational email to an external address |

The SharePoint file download confirmed unauthorized collection of sensitive financial information. However, the available evidence did not establish whether that downloaded file was subsequently transferred through an additional exfiltration mechanism.

Separately, six mailbox messages were confirmed as forwarded to an external address, establishing external disclosure of organizational email data.

## Repository Structure

```text
sentinel-siem-investigation-detection/
├── README.md
├── analysis/
│   └── investigation-notes.md
├── logs/
│   ├── signin-logs.csv
│   ├── m365-activity.csv
│   └── forwarded-email-activity.csv
├── queries/
│   ├── 01-user-baseline.kql
│   ├── 02-source-ip-investigation.kql
│   ├── 03-device-investigation.kql
│   ├── 04-forwarding-analysis.kql
│   └── 05-failed-then-success-detection.kql
└── report/
    ├── README.md
    └── siem-incident-report.pdf

## How to Review This Project

For a quick review of the project, start with the following files:

1. **`README.md`** — Overview of the investigation, key findings, methodology, detection logic, and skills demonstrated.
2. **`analysis/investigation-notes.md`** — Detailed analyst notes documenting the investigation from initial alert through containment and detection engineering.
3. **`queries/`** — Microsoft Sentinel-style KQL queries used to demonstrate authentication analysis, source-IP investigation, device analysis, external forwarding analysis, and detection development.
4. **`logs/`** — Synthetic authentication and Microsoft 365 activity data used as evidence for the investigation.
5. **`report/siem-incident-report.pdf`** — Formal incident report documenting the complete investigation, impact assessment, containment actions, MITRE ATT&CK mapping, and recommendations.

## Project Outcome

The investigation identified a simulated Microsoft 365 account compromise involving suspicious authentication activity, unauthorized access to sensitive business and financial information, and confirmed external disclosure of organizational email.

The project demonstrates an end-to-end SOC workflow:

**Alert Triage → Baseline Analysis → Event Correlation → Scope & Impact Assessment → Containment → MITRE ATT&CK Mapping → Detection Engineering → Incident Documentation**

This project was created to demonstrate practical cybersecurity analysis, security operations, and detection-engineering skills using synthetic data in a safe training environment.
