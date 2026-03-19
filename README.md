# sentinel-brute-force-detection
Microsoft Sentinel detection engineering lab – brute force detection using KQL.
This lab demonstrates how to design and validate a brute-force detection rule using Microsoft Sentinel and Azure AD sign-in logs.
Validation and Testing

Brute-Force Simulation

To validate the detection rule, a brute-force login scenario was simulated against a test user account.

Actions performed:
	•	Opened a private browser session
	•	Attempted multiple failed login attempts against the test account
	•	Ensured all attempts occurred within a five-minute window

Purpose

The objective was to generate authentication failure events in Microsoft Entra ID logs that could be evaluated by the detection rule in Microsoft Sentinel.

Analytics Rule Execution

The analytics rule was configured to run every five minutes.

After generating the failed login attempts, the system was allowed to complete the next scheduled rule evaluation cycle so that the newly generated authentication events could be processed.


Alert Verification

Once the rule executed, the following observations were confirmed:
	•	An alert was successfully generated
	•	The alert contained the affected user account
	•	The alert captured the originating source IP address

This confirmed that the detection logic correctly identified abnormal authentication behavior.


Incident Creation

Incident creation was enabled within the analytics rule configuration.

Following alert generation:
	•	The alert was automatically grouped into an incident
	•	The incident contained the associated alert and relevant entities

This validated the incident automation workflow within Microsoft Sentinel.


Entity Mapping Review

The generated incident was opened for further analysis.

The following entities were reviewed:
	•	User account
	•	Source IP address
	•	Related authentication log entries

Entity mapping provided additional investigation context and enabled a clearer understanding of the authentication activity.


Result

The detection rule successfully identified simulated brute-force authentication activity and generated the expected alert and incident within Microsoft Sentinel.

