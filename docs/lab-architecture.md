# Lab Architecture

This lab simulates a small monitored environment: Windows endpoints generating logs, a log collection layer, and an analyst workstation where triage happens. The goal is to practice the full L1 loop (alert, triage, classify, document, escalate or close) without needing enterprise licensing.

## Components

| Component | Role | Notes |
|---|---|---|
| Windows 10/11 VM | Monitored endpoint | Sysmon installed with a tuned config |
| Wazuh server (OVA or Docker) | SIEM / log collection and rules | Single node is enough for the lab |
| Wazuh agent | Ships Windows Event Log and Sysmon channels | Installed on the Windows VM |
| Analyst machine | Triage, documentation, reporting | Can be the host machine |
| Sample log set (this repo) | Offline practice data | Works without any VM at all |

## Two ways to use the lab

**Full mode (VMs):** deploy Wazuh, enroll a Windows agent with Sysmon, generate benign test activity (failed logons against your own VM, PowerShell test commands, service installs), and watch the alerts come in. Setup steps are in `wazuh-setup-guide.md` and `sysmon-setup-guide.md`.

**Offline mode (no VMs):** use the synthetic logs in `sample-logs/` with the parser in `parser/`. The detection logic mirrors the Sigma rules in `detections/`. This is the fastest way to practice triage decisions and report writing.

## Data flow (full mode)

```
Windows VM (Sysmon + Event Log)
        |
   Wazuh agent
        |
   Wazuh manager (decoders, rules, alerting)
        |
   Wazuh dashboard  -->  analyst triage  -->  incident report
```

## Network layout

Keep everything on an isolated host-only or NAT network. Nothing in this lab needs to be reachable from the internet, and the Wazuh dashboard should never be exposed publicly.

| Host | Example IP |
|---|---|
| Wazuh server | 192.168.56.10 |
| Windows endpoint | 192.168.56.20 |
| Analyst machine | 192.168.56.1 |

All IP addresses in this repo's sample logs are from private ranges (10.x, 192.168.x) or documentation ranges (203.0.113.x, 198.51.100.x). None of them point at real infrastructure.

## Scope and safety

The lab only generates benign activity: wrong-password logon attempts against lab VMs, harmless PowerShell commands, test service installs, and port checks against machines I own. No malware, no exploit code, and no activity against systems outside the lab network.
