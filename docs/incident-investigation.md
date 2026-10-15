# Brute Force Sign-In Detection and Investigation in Microsoft Sentinel

This write-up covers one detection use case, built end to end in Microsoft Sentinel: generating the telemetry, writing the KQL detection, turning it into an analytics rule, and investigating the incident it produced.

## A note on the data

**All telemetry in this project is simulated.** There was no real attacker, no real account and no real sign-in activity. I wrote a Python script that generates synthetic sign-in records and sends them to a custom table in my own Log Analytics workspace. The account (`j.carter@contoso-lab.com`) and the tenant domain are made up.

Testing a detection on injected data is a normal way to prove the logic works before trusting it on real logs. It also let me build the whole pipeline without needing a VM or any live attack tooling. I am being explicit about it because the investigation steps and the detection logic are real skills, and the input data is the only simulated part.

## What I built

```
Python script  ->  Data Collection Endpoint + Rule  ->  SyntheticSignins_CL  ->  Analytics rule  ->  Incident
(synthetic         (Logs Ingestion API)                 (custom table in        (scheduled KQL,     (investigated
 sign-ins)                                               Log Analytics)          MITRE T1110)        in the portal)
```

- **Ingestion:** `scripts/ingest_synthetic_signins.py` authenticates with my own Azure CLI session and uploads records through the Azure Monitor Logs Ingestion API. Each run sends 5 events: 4 failed sign-ins roughly 17 seconds apart, then 1 success, all from the same IP against the same account.
- **Storage:** a custom table, `SyntheticSignins_CL`, with 7 columns: `TimeGenerated`, `UserPrincipalName`, `SourceIP`, `ResultType`, `ResultDescription`, `Location`, `AppDisplayName`.
- **Detection:** a scheduled Sentinel analytics rule that runs the KQL below.
- **Investigation:** incident review, evidence check against the raw logs, classification and triage.

## Detection logic

The query is in `kql-queries/brute-force-signin-detection.kql`:

```kql
SyntheticSignins_CL
| where TimeGenerated > ago(14d)
| summarize
    FailedAttempts = countif(ResultType == "Failure"),
    SuccessAttempts = countif(ResultType == "Success"),
    TotalAttempts = count(),
    FirstFailure = minif(TimeGenerated, ResultType == "Failure"),
    LastEvent = max(TimeGenerated)
    by SourceIP, UserPrincipalName
| extend TimeSpan = LastEvent - FirstFailure
| where TimeSpan < 5m and FailedAttempts >= 4 and SuccessAttempts >= 1
```

In plain words: for each IP and account pair, count the failures and successes, measure how long the activity lasted, and alert if there were at least 4 failures and at least 1 success within 5 minutes. A burst of failures followed by a success from the same source is the classic sign of a guessed password.

## Analytics rule configuration

| Setting | Value |
|---|---|
| Name | Synthetic Brute Force Sign-In Detection |
| Type | Scheduled query rule |
| Severity | Medium |
| MITRE ATT&CK | Credential Access, T1110 Brute Force |
| Schedule | Every 1 day, looking back 14 days |
| Alert threshold | More than 0 results |
| Entity mapping | Account (Name) to `UserPrincipalName`, IP (Address) to `SourceIP` |
| Incident creation | Enabled, alert grouping off |
| Suppression | Off |

The entity mapping is what feeds the investigation graph, so the account and the IP appear as linked entities on the incident.

## What fired

The rule created its first incident on 8 October and then **one more every day until 14 October, 7 incidents in total**. They are all the same detection. See the lessons section for why.

![Incident list filtered to the rule, showing the daily duplicates](../screenshots/02-incident-list-duplicates.png)

## Investigation

**1. Read the incident.** Medium severity, Credential Access, one alert, one impacted user. The incident graph shows `j.carter` linked to `185.220.101.47`, which confirms the entity mapping works.

![Incident graph with the account and the IP](../screenshots/03-incident-graph.png)

**2. Read the alert.** The alert is tagged T1110 and the IP is marked Suspicious in the evidence list. The alert says a pattern was found, but it does not show the logins themselves.

![Alert details, top](../screenshots/04-alert-details-top.png)
![Alert details, bottom](../screenshots/05-alert-details-bottom.png)

**3. Check the raw logs.** I pivoted to the Logs page and queried the table for the IP:

```kql
SyntheticSignins_CL
| where SourceIP == "185.220.101.47"
| order by TimeGenerated asc
```

![Raw events for the suspect IP](../screenshots/01-raw-events-evidence.png)

Timeline from the raw rows (UTC, 1 October):

- 14:03:23, first failed sign-in ("Invalid username or password") to Office 365 Exchange Online
- 7 failures in total before the first success, about 15 to 17 seconds apart
- **14:04:31, first successful sign-in**
- the last event is at 14:04:50, so the whole activity spans 1 minute 27 seconds

Two script runs overlap in this data, which is why a failure and another success appear after the first success. That is an artefact of running the generator twice, not part of the scenario.

**4. Conclusion.** Many failures from one external IP, then a success within minutes, matches a brute force attack that likely ended with a compromised account.

## Analyst note

> Between 2:03 and 2:04 PM UTC on 1 Oct, IP 185.220.101.47 made 7 failed sign-in attempts against j.carter's Office 365 Exchange Online account, about 15 to 17 seconds apart, then signed in successfully at 2:04:31 PM. This matches a brute force attack (T1110) and the account is likely compromised. Recommended actions: reset the password and revoke active sessions, confirm MFA status, block the IP, review what the account did after 2:04:31 PM (mailbox rules, forwarding, other sign-ins), and check whether the same IP targeted other accounts. Telemetry is simulated for this lab.

## Triage outcome

Because the data is a deliberate simulation, I classified the incident as **Informational, expected activity (Security testing)** and not as a true positive. I closed the duplicate incidents with a comment pointing to the original, and kept the oldest one open to test the automation described below.

## Lessons learned

**1. The rule created a duplicate incident every day.** It runs daily with a 14 day lookback, so the same 5 synthetic rows matched on every run until they aged out of the window. Alert grouping and suppression were both off, so Sentinel treated each match as new. Fixes: make the lookback equal to the schedule, or turn on suppression. This is a common real-world tuning problem (alert duplication).

**2. The alert timestamps did not match the real events.** The alert showed first activity 14 days before the rule ran, for example 24 September to 8 October, while the real logins were on 1 October. My query returned no event time column, so Sentinel used the whole query window. The fix is to return the real event time (for example, `LastEvent` as `TimeGenerated`) from the query.

**3. Check the raw data before believing an alert.** The incident alone does not show what happened. The evidence came from going back to the logs and reading the rows.

## Next steps

- Tune the rule to remove the duplicate incidents and fix the alert timestamps.
- Build a SOAR playbook (Logic App) that triggers on this rule, tags the incident and adds an investigation comment, using a managed identity so no credentials are stored.
- Add the playbook definition to `/playbooks` and screenshots of it running.
