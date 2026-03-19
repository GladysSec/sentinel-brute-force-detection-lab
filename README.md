# Brute-Force Detection in Microsoft Sentinel

## Overview
This project demonstrates the design, implementation, and validation of a custom brute-force detection use case in Microsoft Sentinel. The goal was to detect high-frequency failed authentication attempts in Microsoft Entra ID, generate security alerts, and validate the end-to-end incident response workflow.

## Scenario
A controlled brute-force attack was simulated against a non-production test user account. The detection focused on:
- **Volume-based anomalies:** Multiple failed login attempts in a short timeframe  
- **Source-based patterns:** Multiple failures from the same IP targeting one user  

This aligns with MITRE ATT&CK techniques:
- **T1110 – Brute Force**  
- **T1078 – Valid Accounts (post-compromise risk)**

## Tools & Technologies
- **SIEM Platform:** Microsoft Sentinel  
- **Data Source:** Microsoft Entra ID Sign-in Logs (`SigninLogs`)  
- **Query Language:** Kusto Query Language (KQL)  
- **Threat Intelligence Framework:** MITRE ATT&CK

## Detection Logic
A custom analytics rule was created to detect repeated failed logins:

- Threshold: ≥5 failed attempts in 5 minutes per user + IP  
- Rule Frequency: Every 5 minutes  
- Alert triggers when threshold is met  

### Query Example
```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count()
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5

5. Screenshot Reference: KQL Query

![Kql Query](screenshots/kql-query.jpg)
This screenshot shows the KQL query executed in the Log Analytics workspace, demonstrating the query logic and preview of results.
The query was tested in the Microsoft Sentinel Logs blade to validate syntax and expected output before implementing as a scheduled analytics rule.

6. Validation Approach (Simulation)

To trigger the detection rule, a controlled simulation was performed:

Target: A non-production test user account.
Method: Manual entry of incorrect passwords via a private browser session to prevent credential caching and session reuse.
Pacing: 7-10 failed login attempts were executed rapidly within the 5-minute detection window.
Verification: The resulting SigninLogs were confirmed to be ingested into the Sentinel Log Analytics workspace.
7. Screenshot Reference: Timestamp Analysis

![Timestamp-analysis](screenshots/Timestamp-analysis.png)
* This screenshot shows clustered failed login attempts within the 5-minute detection window.This captures the failed sign-in events in the Log Analytics workspace. The timestamps confirm the simulation occurred within the detection timeframe.*
The timestamp analysis validates that all failed attempts were properly logged and fell within a single 5-minute bin, ensuring the aggregation logic would capture them correctly.

8. Investigation & Findings

Upon the next scheduled run of the analytics rule (within 5 minutes of the simulation):

Alert Generation: A security alert was successfully created in Microsoft Sentinel.
Entity Identification: The alert correctly identified the targeted user account and the source IP address based on the by clause in the query.
Contextual Data: The alert details included the count of failed attempts (FailedAttempts) and the 5-minute time window.
Log Correlation: Manual investigation of the raw SigninLogs confirmed the 1:1 correlation between the alert and the simulated brute-force events.
Sample Alert Data:

UserPrincipalName	IPAddress	TimeGenerated (bin)	FailedAttempts
testuser@domain.com
192.168.1.100	2026-01-15 14:05:00	7
9. Screenshot Reference: Generated Alert

![Alert](screenshots/Alert.jpg)
This screenshot shows the security alert as it appears in Microsoft Sentinel. The alert details include the alert name, severity, description, and the entities identified (UserPrincipalName and IPAddress).
The alert screen confirms that the detection logic successfully identified the brute-force pattern and presented it in a format ready for triage.

10. Screenshot Reference: Brute Force Detection Overview

![Brute force](screenshots/Brute-force.png)
This screenshot provides a comprehensive view of the brute-force detection, including the analytics rule configuration, the triggered alert, and the associated incident in the Sentinel interface.
This overview demonstrates the complete detection-to-incident pipeline working as designed.

## 11. Incident Response Workflow

- **Automated Incident Creation:** The security alert was automatically ingested into Microsoft Sentinel's incident queue.
- **Entity Mapping:** While the query provides UserPrincipalName and IPAddress, formal entity mapping in the analytics rule wizard would enhance this further.
- **Triage Enrichment:** An incident playbook could be triggered to enrich the IP address with reputation data or check for related user activity.

**Incident Details:**

Incident Response Workflow:

- Alert automatically grouped into an incident in Microsoft Sentinel
- User account and source IP mapped as entities
- Incident ready for triage and enrichment (IP reputation checks, review of related accounts)

## 12. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|--------------|----------------|-----------|
| **T1110** | Brute Force | Core technique detected by this rule. Specifically, sub-technique T1110.001 (Password Guessing). |
| **T1078** | Valid Accounts | This alert serves as a precursor; a successful brute force could lead to adversary access. |

## 13. Outcome & Success Metrics

The detection rule performed as expected, validating the following key metrics:

| Metric | Result |
|--------|--------|
| **Detection Accuracy** | Successfully identified 100% of simulated brute-force attempts meeting the ≥5 threshold. |
| **Alert Latency** | Alert generated within 5 minutes of the activity window closing. |
| **False Positive Rate** | 0% during controlled testing (requires tuning for production noise). |
| **Query Efficiency** | Simple aggregation pattern ensures performant execution even on large log volumes. |
| **Visual Documentation** | All key stages (query, timestamps, alert, overview) captured for validation. |


## 14. 🎯 Response Actions

- **Block malicious IP addresses** – Prevent further attack attempts from the source
- **Review authentication activity for lateral movement** – Identify if other accounts were targeted
- **Reset or disable targeted accounts if required** – Contain potential compromise
- **Enforce MFA and account lockout policies** – Strengthen authentication security

---

## 15. 🎯 Skills Demonstrated

- **KQL log analysis** – Developed and optimized detection queries
- **SOC alert triage** – Prioritized and investigated security alerts
- **Threat intelligence enrichment** – Correlated IP reputation and failure codes
- **MITRE ATT&CK mapping** – Aligned detection to T1110 and T1078
- **Incident response decision-making** – Executed containment and recovery actions
