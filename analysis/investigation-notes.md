# SIEM Investigation Notes

## Case Overview

This investigation analyzes a simulated Microsoft Sentinel alert involving suspicious authentication activity associated with the account `mlopez@northstarfinancial.com` at the fictional organization Northstar Financial Services.

The investigation uses synthetic telemetry in a Microsoft Sentinel-style environment for cybersecurity training and portfolio purposes. No production systems, accounts, or customer data were used.

## Initial Alert

Microsoft Sentinel generated a Medium-severity alert after multiple failed authentication attempts were followed by a successful authentication.

### Alert Details

- **User:** `mlopez@northstarfinancial.com`
- **Source IP:** `45.83.64.19`
- **Location:** Amsterdam, Netherlands
- **Failed Sign-ins:** 11
- **Successful Sign-ins:** 1
- **Time Window:** 8:31 AM–8:44 AM
- **Device:** Unknown
- **Initial Severity:** Medium

## Initial Analyst Assessment

The alert was treated as an investigative lead rather than immediate proof of account compromise.

Initial investigative questions included:

- Is the source IP normal for M. Lopez?
- Is the source IP associated with other Northstar employees?
- Is Amsterdam consistent with the user's normal authentication activity or approved travel?
- Did the authentication originate from a known corporate device?
- What does the user's recent authentication baseline look like?
## Authentication Baseline Analysis

Recent authentication activity for M. Lopez was reviewed to establish a baseline for normal account behavior.

The user's recent successful sign-ins originated from:

- **Source IP:** `10.24.18.56`
- **Location:** Orlando, US
- **Device:** `NFS-LT-0442`
- **Operating System:** Windows 11
- **Managed Device:** Yes

The authentication associated with the Sentinel alert differed from this recent baseline:

- **Source IP:** `45.83.64.19`
- **Location:** Amsterdam, Netherlands
- **Device:** Unknown
- **Operating System:** Linux
- **Managed Device:** No

The unfamiliar IP address and geographic location increased suspicion but were not treated as sufficient evidence of compromise by themselves.

## Source IP Investigation

Authentication activity associated with `45.83.64.19` was reviewed across the available dataset.

No authentication activity from other Northstar users was identified from this source IP. Within the available telemetry, the IP address was associated only with the suspicious authentication activity involving M. Lopez.

This finding increased the level of suspicion but did not independently establish that the source IP was malicious.

## Device Investigation

Device information associated with the suspicious authentication was compared against the user's recent authentication baseline.

M. Lopez's recent successful activity originated from the managed Windows 11 corporate device `NFS-LT-0442`. In contrast, the suspicious activity originated from an unknown, unmanaged Linux device.

The combination of the following indicators substantially increased confidence that the successful authentication required escalation and further investigation:

- 11 failed authentication attempts
- Successful authentication following the failures
- Previously unobserved source IP
- Unusual geographic location
- Unknown device
- Unmanaged device
- Operating system inconsistent with the user's recent baseline

Based on the combined evidence, the successful authentication was assessed as likely unauthorized account access. Investigation continued to determine the scope and impact of the activity.

## Post-Authentication Activity

Following the suspicious successful authentication at approximately 8:44 AM, Microsoft 365 activity associated with the account was reviewed to determine what occurred during the unauthorized session.

The investigation identified the following activity:

- 8:46 AM — Microsoft Exchange Online accessed
- 8:48 AM — Mailbox searched using the term "invoice"
- 8:50 AM — Email titled "Q3 Vendor Payment Schedule" opened
- 8:52 AM — `Vendor_Payment_Schedule_Q3.xlsx` downloaded
- 8:55 AM — Email titled "October Payroll Processing" opened
- 8:57 AM — `October_Payroll.xlsx` downloaded
- 9:01 AM — SharePoint accessed
- 9:03 AM — Finance/Accounts Payable folder accessed
- 9:06 AM — `Vendor_Banking_Information.xlsx` downloaded
- 9:09 AM — External mailbox forwarding rule created

This activity demonstrated that the unauthorized session progressed beyond account access and included the collection of business and financial information.

## Sensitive Data Assessment

The contents of the accessed and downloaded files were reviewed to determine the sensitivity and potential impact of the exposed information.

### Vendor_Payment_Schedule_Q3.xlsx

The file contained:

- Vendor company names
- Invoice numbers
- Payment amounts
- Scheduled payment dates
- Internal accounts-payable notes

No personal information or bank account information was identified in this file. However, the document contained sensitive internal business and financial information.

### October_Payroll.xlsx

The file contained:

- Employee names
- Employee ID numbers
- Departments
- Gross salary
- Net pay
- Last four digits of employee bank account numbers

The file contained employee PII and sensitive payroll information. Social Security numbers and full employee bank account numbers were not present.

### Vendor_Banking_Information.xlsx

The file contained:

- Vendor company names
- Bank names
- Full routing numbers
- Full bank account numbers
- Accounts-payable contact names
- Contact email addresses

This document represented the most significant financial exposure identified during the investigation because it contained full vendor banking information.

## External Email Forwarding

The unauthorized mailbox forwarding rule directed incoming email to the external address:

`payments.review@external-mail.example`

Review of forwarding activity identified six messages that were forwarded externally before containment.

The forwarded messages included:

- Vendor invoice notification
- Internal meeting reminder
- Vendor payment confirmation
- Employee benefits announcement
- Accounts-payable approval request
- Vendor bank-change request

The external forwarding of these messages confirmed that organizational email data was disclosed outside Northstar's environment.

Of particular concern was the forwarding of an accounts-payable approval request and a vendor bank-change request. Combined with the unauthorized access to vendor payment and banking information, this activity created a significant risk of business email compromise and payment fraud.

No evidence available at this stage confirmed that vendor banking information was modified or that a fraudulent payment occurred.

## Severity Assessment

The original Microsoft Sentinel alert was classified as Medium severity. As additional evidence was identified, the incident severity was escalated to High.

The High-severity assessment was based on:

- Confirmed unauthorized account access
- Successful authentication from an unusual IP address and geographic location
- Authentication from an unknown, unmanaged device
- Unauthorized access to Microsoft 365 and SharePoint resources
- Download of sensitive business, employee, and vendor financial information
- Exposure of full vendor routing and bank account numbers
- Creation of an unauthorized external mailbox forwarding rule
- Confirmed forwarding of six organizational emails to an external address
- Potential risk of business email compromise and payment fraud

Containment did not reduce the severity of the incident because the assessment reflects the confirmed activity and potential impact that occurred during the unauthorized session.

## Containment and Response

Immediate containment actions included:

- Disabled the compromised M. Lopez account
- Revoked active sessions and authentication access
- Initiated a credential reset
- Reviewed the account's authentication and MFA configuration
- Preserved details of the unauthorized mailbox forwarding rule as evidence
- Removed the unauthorized forwarding rule
- Preserved relevant authentication, Microsoft 365, SharePoint, and forwarding activity for further investigation

Following containment, investigation continued to determine the sensitivity of the accessed information and the extent of external disclosure.

## Stakeholder Escalation

Because the incident involved employee information, vendor banking information, external email forwarding, and potential payment-fraud risk, the incident was escalated beyond the SOC.

Appropriate stakeholders included:

- SOC and security leadership
- Finance and Accounts Payable
- Legal, privacy, and compliance personnel as appropriate
- Incident response stakeholders
- Relevant business and data owners

Finance and Accounts Payable should review recent and pending vendor banking changes and payment activity for evidence of unauthorized modification or fraudulent transactions. Any external vendor notification should be coordinated according to organizational incident-response procedures.

## MITRE ATT&CK Mapping

### T1110 — Brute Force

Repeated authentication attempts were observed against the M. Lopez account before a successful authentication occurred.

For this simulated investigation, the activity was assessed as repeated password attempts consistent with brute-force behavior.

### T1114 — Email Collection

Following successful authentication, the unauthorized session accessed Microsoft Exchange Online, searched the mailbox for financial information, opened relevant messages, and downloaded email attachments.

### T1114.003 — Email Forwarding Rule

An unauthorized mailbox forwarding rule was created to send incoming messages to an external email address.

Six messages were confirmed as externally forwarded before containment.

### Additional Collection and External Disclosure

The unauthorized session accessed the Finance/Accounts Payable SharePoint folder and downloaded `Vendor_Banking_Information.xlsx`, which contained full vendor routing and bank account information.

The download confirms unauthorized collection of sensitive financial information. Available evidence does not establish whether the downloaded SharePoint file was subsequently transferred through an additional exfiltration mechanism.

Separately, six mailbox messages were confirmed as forwarded to an external address, establishing external disclosure of organizational email data.

## Detection Engineering

Following the investigation, detection logic was developed to identify similar authentication patterns in the future.

The detection was designed to identify:

- Five or more failed authentication attempts within a 15-minute window
- Attempts involving the same user and source IP
- A successful authentication occurring after the failed attempts
- An unmanaged device OR an unusual geographic location

A five-attempt threshold was selected as a starting point to balance detection sensitivity with potential false positives.

The detection should be enriched with additional organizational context when available, including:

- Known corporate devices and asset inventory
- Corporate and approved VPN IP ranges
- Historical user authentication patterns
- Known network addresses
- Approved employee travel information

Legitimate travel, VPN usage, password-entry mistakes, and authorized temporary devices could produce activity matching portions of the detection logic. Alerts should therefore be treated as investigative leads rather than automatic confirmation of compromise.

Separate detection logic may also be appropriate for high-volume failed authentication activity that does not result in a successful login.

## Final Analyst Conclusion

Microsoft Sentinel generated an alert after 11 failed authentication attempts against the account of M. Lopez were followed by a successful authentication from the same source IP.

Investigation determined that the successful authentication originated from a previously unobserved source IP and geographic location and an unknown, unmanaged Linux device inconsistent with the user's recent authentication baseline. Based on the correlated authentication and device evidence, the activity was assessed as unauthorized account access.

Following authentication, the unauthorized session accessed the user's Microsoft 365 mailbox, searched for financial information, opened email messages, downloaded attachments, and accessed the organization's SharePoint environment. The session accessed the Finance/Accounts Payable folder and downloaded a document containing full vendor routing and bank account information.

An unauthorized external mailbox forwarding rule was also created. Six messages were confirmed as forwarded outside the organization, including an accounts-payable approval request and a vendor bank-change request. This confirmed external disclosure of organizational email data and created additional risk of business email compromise and payment fraud.

Security contained the incident by disabling the compromised account, revoking active sessions and access, resetting account credentials, preserving evidence associated with the unauthorized forwarding rule, and removing the rule.

The incident was escalated to High severity based on the confirmed account compromise, unauthorized access to sensitive business and financial information, exposure of employee and vendor information, and confirmed external forwarding of organizational email.

Available evidence did not establish that a fraudulent payment occurred or that the downloaded SharePoint data was subsequently transferred through another exfiltration mechanism. Further investigation and coordination with appropriate security, Finance, Legal/Compliance, incident response, and business stakeholders were recommended.

## Key Lessons

- SIEM alerts should be treated as investigative leads rather than automatic proof of compromise.
- Authentication baselines help distinguish expected activity from anomalies.
- IP address, location, and device information become more meaningful when correlated together.
- A successful authentication following repeated failures can warrant additional investigation.
- Account compromise investigations should examine post-authentication activity to determine scope and impact.
- File names alone should not be used to determine data sensitivity; document contents should be validated when possible.
- Collection of data and confirmed external disclosure should be documented separately when the evidence supports different conclusions.
- Containment can occur while scope and impact analysis continue.
- Detection rules should balance sensitivity against false positives and incorporate contextual enrichment when possible.
- MITRE ATT&CK techniques should be mapped to observed attacker behaviors rather than applied broadly to an entire incident.
- Incident documentation should distinguish confirmed facts, analytical assessments, and potential risks.
