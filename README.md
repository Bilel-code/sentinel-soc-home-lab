# Microsoft Sentinel SOC Home Lab

A hands-on home lab built to close the Microsoft-tooling gap between my SOC analyst internship experience (Wazuh, MITRE ATT&CK correlation rules, Caldera, Atomic Red Team) and the Microsoft-stack skills (Entra ID, Microsoft Defender for Endpoint, Microsoft Sentinel, KQL) that UK SOC/cyber security job postings keep asking for.

## About me

Final-year MSc Cyber Security student (University of Surrey, expected Feb 2027), currently studying for CompTIA Security+. Completed a 5-month SOC Analyst internship working hands-on with Wazuh SIEM, writing custom correlation rules mapped to MITRE ATT&CK, and using Caldera, Atomic Red Team, and Hydra for adversary emulation.

## What this lab does

- Deploys a Windows Server VM in Azure and onboards it to Microsoft Defender for Endpoint (via Microsoft Defender for Servers), generating and investigating real EDR alerts.
- Deploys Microsoft Sentinel as the SIEM, connects data sources, and implements custom KQL analytics rules — effectively redoing the Wazuh correlation-rule work from my internship, but in the Microsoft stack.
- Builds a SOAR playbook (Azure Logic App) that automatically tags or notifies on a specific alert type.
- Documents the full architecture, detections, and KQL queries below.

## Architecture

_Diagram and write-up in progress — see `/docs`._

## Repo structure

- `/docs` — architecture notes, write-ups, design decisions
- `/kql-queries` — custom KQL analytics rules and hunting queries
- `/screenshots` — evidence of alerts detected and investigated
- `/playbooks` — SOAR/Logic App automation

## Status

🚧 In progress. Built step by step, documented as I go.
