1. Objective

To design, implement, and validate a custom brute-force detection use case in Microsoft Sentinel. The primary goal was to detect high-velocity failed authentication attempts against Microsoft Entra ID (formerly Azure AD) user accounts, automatically generate security alerts, and streamline the incident response process.

2. Scenario & Threat Model

A simulated brute-force attack was conducted against a test user account to validate the detection logic and alert generation pipeline. The exercise focused on identifying:

Volume-based Anomalies: Multiple failed login attempts occurring within a short, defined timeframe.
Source-Based Patterns: A high density of failures originating from a single source IP address targeting a specific user.
This scenario maps directly to the threat of credential stuffing or password guessing attacks (MITRE ATT&CK T1110).

3. Tools & Technologies

SIEM Platform: Microsoft Sentinel
Data Source: Microsoft Entra ID Sign-in Logs (SigninLogs)
Query Language: Kusto Query Language (KQL)
Threat Intelligence Framework: MITRE ATT&CK

4. Detection Logic & KQL Implementation

A custom analytics rule was created in Microsoft Sentinel using the following KQL query. The query identifies all failed sign-in attempts (ResultType != 0), aggregates them by user, source IP, and 5-minute time bins, then filters for thresholds indicating malicious activity.

Detection Logic Breakdown:

Step 1: Filter for all failed sign-in events (ResultType != 0).
Step 2: Aggregate counts by user, source IP, and 5-minute time windows.
Step 3: Retain only results where failed attempts meet or exceed the threshold (≥5).
Analytics Rule Settings:

Rule Frequency: Run query every 5 minutes.
Lookback Period: Look at data from the last 5 minutes.
Alert Threshold: Generate alert when query results > 0 (i.e., when any row meets the ≥5 condition).
KQL Query (queries/brute-force.kql):

kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count()
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
Query Explanation:

Component	Purpose
where ResultType != 0	Filters for all failed sign-in attempts (non-zero result codes)
summarize FailedAttempts = count()	Counts the number of failures
by UserPrincipalName, IPAddress	Groups by specific user and source IP
bin(TimeGenerated, 5m)	Creates 5-minute time windows for aggregation
where FailedAttempts >= 5	Threshold filter—alerts on 5+ failures in 5 minutes

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
*This screenshot captures the failed sign-in events in the Log Analytics workspace, showing the timestamps of each failed attempt clustered within the 5-minute window. The timestamps confirm the simulation occurred within the detection timeframe.*
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

| Field | Value |
|-------|-------|
| **Incident ID** | INC-12345 |
| **Alert Name** | Brute Force Attempt Detected |
| **Severity** | Medium |
| **Status** | New |
| **Owner** | [Assigned Analyst] |
| **Created Time** | 2024-01-15 14:10:00 UTC |

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

