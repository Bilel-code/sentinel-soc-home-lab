# Microsoft Sentinel SOC Home Lab

A hands-on home lab built to close the Microsoft-tooling gap between my SOC analyst internship experience (Wazuh, MITRE ATT&CK correlation rules, Caldera, Atomic Red Team) and the Microsoft-stack skills (Entra ID, Microsoft Sentinel, KQL) that UK SOC/cyber security job postings keep asking for.

## About me

Final-year MSc Cyber Security student (University of Surrey, expected Feb 2027), currently studying for CompTIA Security+. Completed a 5-month SOC Analyst internship working hands-on with Wazuh SIEM, writing custom correlation rules mapped to MITRE ATT&CK, and using Caldera, Atomic Red Team, and Hydra for adversary emulation.

## What this lab does

- Deploys a Microsoft Sentinel environment in Azure (Log Analytics workspace + Sentinel enabled as the SIEM) and builds a custom detection engineering pipeline from scratch, rather than relying on a pre-built sample dataset.
- Ingests synthetic security telemetry — a simulated brute-force sign-in pattern mapped to MITRE ATT&CK T1110 (Brute Force) — into a custom Log Analytics table via Azure Monitor's **Logs Ingestion API**: a Data Collection Endpoint, a Data Collection Rule, and a Python ingestion script (`azure-identity` + `azure-monitor-ingestion` SDKs), authenticated through an Azure AD RBAC role assignment rather than a stored credential.
- Writes custom KQL detection queries and Sentinel Analytics Rules against that data, producing real Sentinel incidents to investigate — effectively redoing the Wazuh correlation-rule work from my internship, but in the Microsoft stack.
- (Stretch goal) Builds a SOAR playbook (Azure Logic App) that automatically tags or notifies on a specific alert type.
- Documents the full architecture, detection logic, and KQL queries below.

## Architecture

_Diagram and write-up in progress — see `/docs`._

## Repo structure

- `/scripts` — Python ingestion script that generates and pushes synthetic telemetry via the Logs Ingestion API
- `/docs` — architecture notes, write-ups, design decisions
- `/kql-queries` — custom KQL analytics rules and hunting queries
- `/screenshots` — evidence of alerts detected and investigated
- `/playbooks` — SOAR/Logic App automation

## Status

🚧 In progress. Built step by step, documented as I go.
