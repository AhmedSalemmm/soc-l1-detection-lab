# Detection Rules

Sigma rules covering the scenarios in this lab. Sigma is a vendor-neutral YAML format for describing log detections; rules written once can be converted to Wazuh, Splunk, Elastic, or Sentinel queries with sigconverter or pySigma backends.

Rules that need thresholds over time (spikes, sprays, scans) are written as a base event rule plus a Sigma correlation document in the same file. Rules that match a single event stand alone. Every rule lists its false positive candidates, because a detection without documented FP cases is only half written.

| Rule file | Catches | Log source | MITRE | Level |
|---|---|---|---|---|
| failed-login-spike.yml | 6+ failed logons from one source in 2 minutes | Windows Security 4625 | T1110.001 | medium |
| credential-attack-pattern.yml | One source failing against 5+ accounts in 10 minutes (spray) | Windows Security 4625 | T1110.003 | high |
| suspicious-powershell-command.yml | Encoded or download-and-execute PowerShell command lines | Sysmon 1 / process creation | T1059.001, T1027 | high |
| suspicious-process-execution.yml | Office apps spawning cmd, PowerShell, or script hosts | Sysmon 1 / process creation | T1204.002 | high |
| new-service-creation.yml | Service installed with binary in a user or temp path | Windows System 7045 | T1543.003 | high |
| port-scan-indicators.yml | One source hitting 10+ ports in 1 minute | Firewall | T1046 | medium |
| unusual-outbound-connection.yml | Scripting processes connecting out on uncommon ports | Sysmon 3 / network connection | T1571 | high |

## Design choices

- **Field-based only.** Rules match log fields and patterns. There is no exploit logic anywhere; everything here is defensive.
- **Thresholds are lab-sized.** Six failures in two minutes is right for a quiet lab. A production environment needs these tuned against real baseline volume before deployment.
- **False positives documented up front.** Each rule's `falsepositives` section is the starting checklist for triage, and pairs with the playbook for that scenario in `playbooks/`.
- **Narrow MITRE tags.** Techniques are tagged only where the matched behavior is direct evidence. Reasoning is in `docs/mitre-attack-mapping.md`.

The parser in `parser/` implements the same logic in Python against the synthetic logs in `sample-logs/`, so every rule here can be demonstrated end to end without a SIEM.
